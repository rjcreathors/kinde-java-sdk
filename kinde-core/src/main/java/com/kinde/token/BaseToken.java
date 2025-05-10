package com.kinde.token;

import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

@Slf4j
public class BaseToken implements KindeToken {

    private String token;
    private boolean valid;
    private SignedJWT signedJWT;

    @SneakyThrows
    protected BaseToken(String token, boolean valid) {
        this.token = token;
        this.valid = valid;
        try {
            signedJWT = SignedJWT.parse(this.token);
        } catch (ParseException e) {
            log.error("There was an error while parsing the JWT", e);
            signedJWT = null;
        }
    }

    @Override
    public boolean valid() {
        return valid;
    }

    public String token() {
        return this.token;
    }

    @Override
    @SneakyThrows
    public String getUser() {
        return this.signedJWT.getJWTClaimsSet().getSubject();
    }

    @Override
    public List<String> getOrganisations() {
        return (List<String>)this.getClaim("org_codes");
    }

    @SneakyThrows
    public Object getClaim(String key) {
        return this.signedJWT.getJWTClaimsSet().getClaim(key);
    }

    public List<String> getPermissions() {
        return (List<String>) getClaim("permissions");
    }

    @Override
    public String getStringFlag(String key) {
        return (String)getFlagClaims().get(key);
    }

    @Override
    public Integer getIntegerFlag(String key) {
        return getFlagClaims().get(key) != null ? ((Long)getFlagClaims().get(key)).intValue() : null;
    }

    @Override
    public Boolean getBooleanFlag(String key) {
        return (Boolean) getFlagClaims().get(key);
    }

    private Map<String,Object> getFlagClaims() {
        return ((Map<String,Object>)getClaim("feature_flags"));
    }

    public Map<String,Object> getFlags() {
        return (Map<String,Object>) getClaim("feature_flags");
    }
}
