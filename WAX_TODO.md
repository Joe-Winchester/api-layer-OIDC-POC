**Done:**

Forked Zowe APIML.   
- Modified ZAAS so that it can accept a JWT from WAX and accept REST APIs with that and create a passticket

Modified code so that
- issuer wasn't a valid URI
`apiml-security-common/src/main/java/org/zowe/apiml/security/common/token/QueryResponse.java`
```
  if (UrlUtils.isValidUrl(issuer) || StringUtils.equalsIgnoreCase(issuer, "KNOXSSO")) {
                return OIDC;
            }
```

- added bypass and PEM URL to the config
`zaas-service/src/main/java/org/zowe/apiml/zaas/security/service/token/OIDCTokenProviderJWK.java`


Modified the runtime
    
- Added a service called IBM z/OSMF Passticket that introduced the basepath `ibmzosmfpassticket/api` 

This was done by editing [`/components/discovery/bin/manifest.mf`](./mods/runtime/manifest.mf)

```
apimlServices:
  dynamic:
    - serviceId: discovery
  static:
    - file: zosmf-static-definition.yaml.template
    - file: passticket-static-definition.yaml.template
```

and the file contents for the static service are at [`/components/discovery/bin/manifest.mf`](./mods/runtime/passticket-static-definition.yaml.template)

**Problems**

***Don't have this as a derivative work - contribute with extensions***

This code is a derivative work of Zowe.org which isn't allowed and prevents delivery due to the EPL 2.0 weak copy left license.   
We must deliver this back to zowe.org in a way that unmodified code can be configured with our behavior.

***Don't have this as static registration - make it dynamic for z/OSMF ***

Currently the introduction of `/zosmfpassticket/api/v1:443` endpoint is done by modifying runtime code.  Make this a dynamic introduction of the service


***We made this work for z/OSMF - what about other endpoints ***

CICS,  Db2,  OMEGAMON,  Workload Scheduler,  NetView,   &C.

***What about an end to end flow from a WAX client***

We made this work for a REST API from insomnia/postman/curl to exchange a JWT token for a passticket which is great, but we haven't shown it work for an end to end from a WAX client to z/OS.

**Packaging**

The current stack involves installing Zowe v3 on z/OS.  
For a more streamlined deployment we'd like to have a more lightweight z/OS experience, ideally a .WAR file that can be packaged and launched with WAX.