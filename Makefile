.PHONY: tests run-tests clean

tests:	
		docker-compose build

run-tests:	
		docker-compose up -d
		docker-compose logs --follow oidcish_tests

clean:	
		docker stop oidc-server-mock; \
		docker rm oidc-server-mock; \
		docker stop oidcish-tests; \
		docker rm oidcish-tests
