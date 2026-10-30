.PHONY: install migrate api dashboard
install:
	python -m pip install -e '.[dev]'
migrate:
	alembic upgrade head
api:
	apisentinel serve
dashboard:
	cd dashboard && npm run dev
