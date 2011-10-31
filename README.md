# Shibboleth IDP Postlogin Flow Plugin

This is a Shibboleth IDP plugin Servlet Filter project that intercepts Shibboleth IDP SSO Profile request and forwards them if necessry to an external 'post login flow' endpoint responsible for actions such as SAML attributes-based authorization, attributes release consent, terms of use acceptance, or anything else that might become required for any particular Shibboleth Idp deployer. Currently there is a default post login flow [project](https://github.com/dima767/Shibboleth-IDP-Postlogin-Flow)

For implementation details see `PostLoginFlowFilter` javadocs

This project uses [Gradle](http://gradle.org) build system

	
To build
--------
Simply run `./gradlew jar`

The jar is then available in `build/libs/Shibboleth-IDP-Postlogin-Filter.jar`

To enable this filter
-------------------
* Enable Tomcat's *crosscontext* in `$CATALINA_HOME/conf/context.xml`

```xml
<Context crossContext="true">
	...
</Context>
```

* Enable Tomcat's SSL Connector's *emptySessionPath* in `$CATALINA_HOME/conf/server.xml`

```xml
<Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true" emptySessionPath="true" .../>
```

* Make sure that IDP is deployed and war is exploded as `$CATALINA_HOME/webapps/idp`
* Make sure that the default post login flow is deployed as `$CATALINA_HOME/webapps/plf.war`
* Add the following filter entry in `$CATALINA_HOME/webapps/idp/WEB-INF/web.xml`

```xml
	<filter>
        <filter-name>PostLoginFlowFilter</filter-name>
        <filter-class>edu.internet2.middleware.shibboleth.idp.profile.saml2.PostLoginFlowFilter</filter-class>
    </filter>
    <filter-mapping>
        <filter-name>PostLoginFlowFilter</filter-name>
        <url-pattern>/profile/*</url-pattern>
   </filter-mapping>
```
* Drop previously built `Shibboleth-IDP-Postlogin-Filter.jar` into `$CATALINA_HOME/webapps/idp/WEB-INF/lib`