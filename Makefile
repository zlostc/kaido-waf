# ⚔️ Kaido WAF — Makefile

.PHONY: install run docker-build docker-run clean

install:
	pip install -r requirements.txt

run:
	python3 -m kaido_waf.main

docker-build:
	docker build -t kaido-waf:latest .

docker-run:
	docker run -d --name kaido-waf \
		-p 8080:8080 \
		-p 9090:9090 \
		-v $(PWD)/config.yaml:/etc/kaido-waf/config.yaml \
		kaido-waf:latest

docker-compose-up:
	docker-compose -f examples/docker-compose.yml up -d

docker-compose-down:
	docker-compose -f examples/docker-compose.yml down

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null
	find . -type f -name "*.pyc" -delete
	rm -rf *.egg-info build dist

test:
	python3 -m pytest tests/ -v
