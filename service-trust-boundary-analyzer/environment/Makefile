.PHONY: build run clean

BINARY := /app/build/trustbound

build:
	@mkdir -p /app/build
	cd /app && go build -o build/trustbound ./cmd/trustbound

run: build
	/app/build/trustbound

clean:
	rm -f /app/build/trustbound /app/build/service_trust_boundary_report.json
