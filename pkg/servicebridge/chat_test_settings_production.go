//go:build !roomtest

package servicebridge

// chatTestSettings is false in a production build: it refuses the chat test
// card lifetime.
const chatTestSettings = false
