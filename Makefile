PKG := github.com/TheRebelOfBabylon/weirwood

GOBUILD := GO111MODULE=on go build -v
GOINSTALL := GO111MODULE=on go install -v

# ============
# INSTALLATION
# ============

build:
	$(GOBUILD) -o weirwood-debug $(PKG)/cmd/weirwood
	$(GOBUILD) -o heartcli-debug $(PKG)/cmd/heartcli

install:
	$(GOINSTALL) $(PKG)/cmd/weirwood
	$(GOINSTALL) $(PKG)/cmd/heartcli