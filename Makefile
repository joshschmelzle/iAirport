PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
LIBEXECDIR ?= $(PREFIX)/libexec
DATADIR ?= $(PREFIX)/share/iairport
CODESIGN_IDENTITY ?= -
SWIFT_BUILD_FLAGS ?=
APPDIR := build/iairport.app

.PHONY: all build bundle test install uninstall clean

all: bundle

build:
	swift build -c release $(SWIFT_BUILD_FLAGS)

bundle: build
	rm -rf "$(APPDIR)"
	install -d "$(APPDIR)/Contents/MacOS" "$(APPDIR)/Contents/Resources"
	install -m 0755 .build/release/iairport "$(APPDIR)/Contents/MacOS/iairport"
	install -m 0644 Resources/Info.plist "$(APPDIR)/Contents/Info.plist"
	install -m 0644 oui.txt "$(APPDIR)/Contents/Resources/oui.txt"
	codesign -s "$(CODESIGN_IDENTITY)" -f "$(APPDIR)"

test:
	swift test

install:
	@test -d "$(APPDIR)" || { echo "error: $(APPDIR) not found. Run 'make' first, then 'sudo make install'." >&2; exit 1; }
	install -d "$(BINDIR)" "$(LIBEXECDIR)" "$(DATADIR)"
	rm -rf "$(LIBEXECDIR)/iairport.app"
	cp -R "$(APPDIR)" "$(LIBEXECDIR)/iairport.app"
	ln -sfn "$(LIBEXECDIR)/iairport.app/Contents/MacOS/iairport" "$(BINDIR)/iairport"
	install -m 0644 oui.txt "$(DATADIR)/oui.txt"

uninstall:
	rm -f "$(BINDIR)/iairport" "$(DATADIR)/oui.txt"
	rm -rf "$(LIBEXECDIR)/iairport.app"

clean:
	swift package clean
	rm -rf build
