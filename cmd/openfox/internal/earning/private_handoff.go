package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tosnetwork/openfox/pkg/config"
	openfoxearning "github.com/tosnetwork/openfox/pkg/earning"
	"github.com/tosnetwork/tos-ai/pkg/privateingress"
	"github.com/tosnetwork/tos-messenger/pkg/localapi"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type privateHandoffRuntime struct {
	Autonomy *openfoxearning.PrivateHandoffAutonomy
	Ingress  *privateingress.Store
	Server   *http.Server
	Listener net.Listener
	Done     chan error
	once     sync.Once
}

func (runtime *privateHandoffRuntime) Close() {
	if runtime == nil {
		return
	}
	runtime.once.Do(func() {
		if runtime.Server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = runtime.Server.Shutdown(ctx)
			cancel()
		}
		if runtime.Listener != nil {
			_ = runtime.Listener.Close()
		}
		if runtime.Ingress != nil {
			_ = runtime.Ingress.Close()
		}
	})
}

func openPrivateHandoffRuntime(settings config.EarningSettings, engine *openfoxearning.Engine, messenger *localapi.Client,
	identityKey ed25519.PrivateKey, authorities openfoxearning.PinnedIntentAuthorities,
	fence openfoxearning.WriterFenceProvider) (*privateHandoffRuntime, error) {
	configured := settings.PrivateHandoff
	if !configured.Enabled {
		return nil, nil
	}
	if engine == nil || messenger == nil || len(identityKey) != ed25519.PrivateKeySize || authorities == nil || fence == nil {
		return nil, errors.New("private handoff runtime dependencies are incomplete")
	}
	runtime := &privateHandoffRuntime{}
	autonomy := &openfoxearning.PrivateHandoffAutonomy{Engine: engine,
		Inbox: openfoxearning.PrivateHandoffInbox{Client: messenger}, Fence: fence, PolicyRevision: 1}
	runtime.Autonomy = autonomy
	if configured.IngressListen != "" {
		directory := filepath.Join(settings.StateDir, "private-ingress")
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return nil, err
		}
		ingress, err := privateingress.Open(directory, settings.AgentID, identityKey, authorities, engine.Authority)
		if err != nil {
			return nil, err
		}
		runtime.Ingress = ingress
		receiver := &openfoxearning.PrivateHandoffService{Engine: engine, Ingress: ingress}
		autonomy.Receiver = receiver
		autonomy.ReceiverPolicy = openfoxearning.PrivateHandoffReceiverPolicy{IngressProfileURI: configured.IngressProfileURI,
			IngressInstanceID: configured.IngressInstanceID, PurposeDigest: configured.PurposeDigest,
			RetentionPolicyDigest: configured.RetentionPolicyDigest, MaximumPlaintextBytes: configured.MaximumPlaintextBytes,
			MaximumFiles: configured.MaximumFiles, AcceptedMediaTypes: append([]string(nil), configured.AcceptedMediaTypes...),
			ChallengeTTL: time.Duration(configured.ChallengeTTLSeconds) * time.Second,
			RetentionTTL: time.Duration(configured.RetentionTTLSeconds) * time.Second}
		handler := openfoxearning.PrivateIngressHTTPHandler{IngressInstanceID: configured.IngressInstanceID,
			MaximumBodyBytes: int64(configured.MaximumPlaintextBytes*2 + (2 << 20)),
			Accept: func(ctx context.Context, challenge commerce.SignedPrivateHandoffChallenge,
				authorization commerce.SignedPrivateHandoffAuthorization, ciphertext []byte) (commerce.SignedPrivateHandoffAcknowledgement, error) {
				current, err := fence(ctx)
				if err != nil {
					return commerce.SignedPrivateHandoffAcknowledgement{}, err
				}
				ack, _, resolution, err := receiver.AcceptAndSendAcknowledgement(ctx, challenge, authorization, ciphertext, 1, current)
				if err != nil || resolution.State != commerce.ActionAccepted && resolution.State != commerce.ActionTerminal {
					return commerce.SignedPrivateHandoffAcknowledgement{}, errors.New("private ingress acknowledgement was not durably sent")
				}
				return ack, nil
			}}
		listener, err := net.Listen("tcp", configured.IngressListen)
		if err != nil {
			runtime.Close()
			return nil, err
		}
		runtime.Listener = listener
		if configured.IngressTLSCertFile != "" {
			certificatePEM, certErr := readBoundedRegular(configured.IngressTLSCertFile, 1<<20, false)
			keyPEM, keyErr := readBoundedRegular(configured.IngressTLSKeyFile, 1<<20, true)
			if certErr != nil || keyErr != nil {
				runtime.Close()
				return nil, errors.New("private ingress TLS identity is invalid")
			}
			certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
			zeroBytes(keyPEM)
			if err != nil {
				runtime.Close()
				return nil, errors.New("private ingress TLS identity is invalid")
			}
			listener = tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13,
				Certificates: []tls.Certificate{certificate}, SessionTicketsDisabled: true})
			runtime.Listener = listener
		}
		runtime.Server = &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute,
			WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10}
		runtime.Done = make(chan error, 1)
		go func() { runtime.Done <- runtime.Server.Serve(runtime.Listener) }()
		autonomy.Health = func() error {
			select {
			case err := <-runtime.Done:
				if errors.Is(err, http.ErrServerClosed) {
					return nil
				}
				return err
			default:
				return nil
			}
		}
	}
	if len(configured.Uploaders) != 0 {
		uploaders := openfoxearning.PrivateContentUploaderSet{}
		for _, item := range configured.Uploaders {
			var roots *x509.CertPool
			if item.CAFile != "" {
				pem, err := readBoundedRegular(item.CAFile, 4<<20, false)
				if err != nil {
					runtime.Close()
					return nil, err
				}
				roots = x509.NewCertPool()
				if !roots.AppendCertsFromPEM(pem) {
					runtime.Close()
					return nil, errors.New("private uploader CA contains no certificate")
				}
			}
			uploader, err := openfoxearning.NewHTTPPrivateContentUploader(item.IngressInstanceID, item.Endpoint, roots,
				item.MaximumCiphertext, item.AllowLoopbackHTTP)
			if err != nil {
				runtime.Close()
				return nil, err
			}
			uploaders[item.IngressInstanceID] = uploader
		}
		autonomy.Sender = &openfoxearning.PrivateHandoffSenderService{Engine: engine, Uploader: uploaders,
			Resolver: authorities, SenderKey: identityKey}
		inputs := make(map[string]openfoxearning.FilePrivateHandoffInput, len(configured.Inputs))
		for _, input := range configured.Inputs {
			inputs[input.ObligationID] = openfoxearning.FilePrivateHandoffInput{ObligationID: input.ObligationID,
				Path: input.Path, MediaType: input.MediaType, CanonicalPath: input.CanonicalPath, MaximumBytes: input.MaximumBytes,
				MaximumExpandedBytes: input.MaximumExpandedBytes, CompressionProfile: input.CompressionProfile}
		}
		autonomy.Content = openfoxearning.FilePrivateHandoffContentSource{Inputs: inputs}
	}
	return runtime, nil
}
