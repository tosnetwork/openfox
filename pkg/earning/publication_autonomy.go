package earning

import (
	"context"
	"errors"
)

type PublicationAutonomy struct {
	Manager    *PublicationManager
	CarrierIDs []string
	Fence      WriterFenceProvider
}

func (service PublicationAutonomy) Process(ctx context.Context) (bool, PublicationRecord, error) {
	if service.Manager == nil || len(service.CarrierIDs) == 0 || service.Fence == nil {
		return false, PublicationRecord{}, errors.New("publication autonomy is incomplete")
	}
	fence, err := service.Fence(ctx)
	if err != nil {
		return false, PublicationRecord{}, err
	}
	record, changed, err := service.Manager.MaintainSupply(ctx, service.CarrierIDs, 1, fence)
	return changed, record, err
}
