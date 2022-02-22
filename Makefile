build:
	rm -rf dist
	yarn run build

test:
	yarn run test

publish: build
publish:
	npm publish --access public
