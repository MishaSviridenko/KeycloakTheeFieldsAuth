package com.sid.keycloakauthenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;

import javax.ws.rs.core.MultivaluedMap;

public class UsernameCompanyPasswordForm extends UsernamePasswordForm implements Authenticator {

    @Override
    public boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        return validateUserAndPassword(context, formData) && validateCompanyLogin(context, formData);
    }

    private boolean validateCompanyLogin(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        String company = inputData.getFirst("company");
        if (company == null || !company.equals("qw")) {
            context.getEvent().error("company_not_found");
            return false;
        }
        return true;
    }

}
