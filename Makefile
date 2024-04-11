# PROG:=tem
VERSION:=`cat ./VERSION`
COMMIT:=`git describe --dirty=+WiP --always`
APPDATE=`date +"%Y-%m-%d-%H:%M"`
GOFLAGS:=-v -ldflags "-X app.version=$(VERSION)-$(COMMIT)"

GOOS ?= $(shell uname -s | tr A-Z a-z)

GO:=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go

build:	gen-mqtt-msg-new-qname.go
	/bin/sh make-version.sh $(VERSION)-$(COMMIT) $(APPDATE) 

gen-mqtt-msg-new-qname.go: checkout/events-mqtt-message-new_qname.json
	go-jsonschema checkout/events-mqtt-message-new_qname.json --package tapir --tags json --only-models --output gen-mqtt-msg-new-qname.go

# gen-mqtt-msg.go: checkout/events-mqtt-message.json
#	go-jsonschema checkout/events-mqtt-message.json --package tapir --tags json --only-models --output gen-mqtt-msg.go

checkout/events-mqtt-message-new_qname.json: checkout
	cd checkout; python schemasplit.py events-mqtt-message-new_qname.yaml

checkout/events-mqtt-message.json: checkout
	cd checkout; python schemasplit.py events-mqtt-message.yaml

checkout:
	git clone git@github.com:dnstapir/protocols.git checkout

clean:
	@rm -f $(PROG) *~

.PHONY: build clean generate

