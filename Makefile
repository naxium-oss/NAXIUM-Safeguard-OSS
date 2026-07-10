.PHONY: install build dev test lint typecheck coverage ci docker-build docker-up docker-down cli clean headers

install:
	npm install --legacy-peer-deps

typecheck:
	npm run typecheck

lint:
	npm run lint

build:
	npm run build

dev:
	npm run dev

test:
	npm test

coverage:
	npm run test:coverage

ci:
	npm run ci

headers:
	npm run headers

cli:
	npm run cli -- $(ARGS)

docker-build:
	docker build -t naxium-safeguard-oss .

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

clean:
	rm -rf dist coverage node_modules
