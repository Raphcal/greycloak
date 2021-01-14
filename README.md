# Greycloak

Greycloak is a basic OAuth2 authentification server. It is somewhat a mock
version of Keycloak.

It does not need any configuration and can be used during development instead of
Keycloak to reduce the number of servers a developer has to install and setup
before being able to work.

## Getting started
You can run Greycloak using the `exec` plugin of Maven:
~~~bash
mvn exec:java -Dexec.mainClass=com.github.raphcal.greycloak.Main
~~~
