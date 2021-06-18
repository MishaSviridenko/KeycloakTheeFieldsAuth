package com.sid.keycloakauthenticator;

import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
//import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

public class UsernameCompanyPasswordForm  implements Authenticator { //extends UsernamePasswordForm

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

    public boolean validateUserAndPassword(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        context.clearUser();
        UserModel user = this.getUser(context, inputData);
        return user != null && this.validatePassword(context, user, inputData) && this.validateUser(context, user, inputData);
    }

    private UserModel getUser(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        String username = (String)inputData.getFirst("username");
        if (username == null) {
            context.getEvent().error("user_not_found");
            Response challengeResponse = this.challenge(context, this.getDefaultChallengeMessage(context), "username");
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return null;
        } else {
            username = username.trim();
            context.getEvent().detail("username", username);
            context.getAuthenticationSession().setAuthNote("ATTEMPTED_USERNAME", username);
            UserModel user = null;

            try {
                user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
            } catch (ModelDuplicateException var6) {
                ServicesLogger.LOGGER.modelDuplicateException(var6);
                if (var6.getDuplicateFieldName() != null && var6.getDuplicateFieldName().equals("email")) {
                    this.setDuplicateUserChallenge(context, "email_in_use", "emailExistsMessage", AuthenticationFlowError.INVALID_USER);
                } else {
                    this.setDuplicateUserChallenge(context, "username_in_use", "usernameExistsMessage", AuthenticationFlowError.INVALID_USER);
                }

                return user;
            }

            this.testInvalidUser(context, user);
            return user;
        }
    }

    public boolean validatePassword(AuthenticationFlowContext context, UserModel user, MultivaluedMap<String, String> inputData) {
        return this.validatePassword(context, user, inputData, true);
    }

    public boolean validatePassword(AuthenticationFlowContext context, UserModel user, MultivaluedMap<String, String> inputData, boolean clearUser) {
        String password = (String)inputData.getFirst("password");
        if (password != null && !password.isEmpty()) {
            if (this.isTemporarilyDisabledByBruteForce(context, user)) {
                return false;
            } else {
                return password != null && !password.isEmpty() && context.getSession().userCredentialManager().isValid(context.getRealm(), user, new CredentialInput[]{UserCredentialModel.password(password)}) ? true : this.badPasswordHandler(context, user, clearUser, false);
            }
        } else {
            return this.badPasswordHandler(context, user, clearUser, true);
        }
    }



    public boolean validateUser(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        context.clearUser();
        UserModel user = this.getUser(context, inputData);
        return user != null && this.validateUser(context, user, inputData);
    }

    private boolean validateUser(AuthenticationFlowContext context, UserModel user, MultivaluedMap<String, String> inputData) {
        if (!this.enabledUser(context, user)) {
            return false;
        } else {
            String rememberMe = (String)inputData.getFirst("rememberMe");
            boolean remember = rememberMe != null && rememberMe.equalsIgnoreCase("on");
            if (remember) {
                context.getAuthenticationSession().setAuthNote("remember_me", "true");
                context.getEvent().detail("remember_me", "true");
            } else {
                context.getAuthenticationSession().removeAuthNote("remember_me");
            }

            context.setUser(user);
            return true;
        }
    }

    public boolean enabledUser(AuthenticationFlowContext context, UserModel user) {
        if (!user.isEnabled()) {
            context.getEvent().user(user);
            context.getEvent().error("user_disabled");
            Response challengeResponse = this.challenge(context, "accountDisabledMessage");
            context.forceChallenge(challengeResponse);
            return false;
        } else {
            return !this.isTemporarilyDisabledByBruteForce(context, user);
        }
    }

    protected Response challenge(AuthenticationFlowContext context, String error) {
        return this.challenge(context, error, (String)null);
    }

    protected Response challenge(AuthenticationFlowContext context, String error, String field) {
        LoginFormsProvider form = context.form().setExecution(context.getExecution().getId());
        if (error != null) {
            if (field != null) {
                form.addError(new FormMessage(field, error));
            } else {
                form.setError(error, new Object[0]);
            }
        }

        return this.createLoginForm(form);
    }

    protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
        return "invalidUserMessage";
    }

    protected Response createLoginForm(LoginFormsProvider form) {
        return form.createLoginUsernamePassword();
    }

    private boolean badPasswordHandler(AuthenticationFlowContext context, UserModel user, boolean clearUser, boolean isEmptyPassword) {
        context.getEvent().user(user);
        context.getEvent().error("invalid_user_credentials");
        Response challengeResponse = this.challenge(context, this.getDefaultChallengeMessage(context), "password");
        if (isEmptyPassword) {
            context.forceChallenge(challengeResponse);
        } else {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
        }

        if (clearUser) {
            context.clearUser();
        }

        return false;
    }

    protected boolean isTemporarilyDisabledByBruteForce(AuthenticationFlowContext context, UserModel user) {
        if (context.getRealm().isBruteForceProtected() && context.getProtector().isTemporarilyDisabled(context.getSession(), context.getRealm(), user)) {
            context.getEvent().user(user);
            context.getEvent().error("user_temporarily_disabled");
            Response challengeResponse = this.challenge(context, this.tempDisabledError(), this.tempDisabledFieldError());
            context.forceChallenge(challengeResponse);
            return true;
        } else {
            return false;
        }
    }

    protected Response setDuplicateUserChallenge(AuthenticationFlowContext context, String eventError, String loginFormError, AuthenticationFlowError authenticatorError) {
        context.getEvent().error(eventError);
        Response challengeResponse = context.form().setError(loginFormError, new Object[0]).createLoginUsernamePassword();
        context.failureChallenge(authenticatorError, challengeResponse);
        return challengeResponse;
    }

    protected String tempDisabledError() {
        return "invalidUserMessage";
    }

    protected String tempDisabledFieldError() {
        return "username";
    }

    public void testInvalidUser(AuthenticationFlowContext context, UserModel user) {
        if (user == null) {
            this.dummyHash(context);
            context.getEvent().error("user_not_found");
            Response challengeResponse = this.challenge(context, this.getDefaultChallengeMessage(context), "username");
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
        }

    }

    protected void dummyHash(AuthenticationFlowContext context) {
        PasswordPolicy policy = context.getRealm().getPasswordPolicy();
        if (policy == null) {
            this.runDefaultDummyHash(context);
        } else {
            PasswordHashProvider hash = (PasswordHashProvider)context.getSession().getProvider(PasswordHashProvider.class, policy.getHashAlgorithm());
            if (hash == null) {
                this.runDefaultDummyHash(context);
            } else {
                hash.encode("dummypassword", policy.getHashIterations());
            }
        }
    }

    protected void runDefaultDummyHash(AuthenticationFlowContext context) {
        PasswordHashProvider hash = (PasswordHashProvider)context.getSession().getProvider(PasswordHashProvider.class, "pbkdf2-sha256");
        hash.encode("dummypassword", 27500);
    }


    @Override
//    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
//
//    }
    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
        String loginHint = context.getAuthenticationSession().getClientNote("login_hint");
        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getRealm(), context.getHttpRequest().getHttpHeaders());
        if (loginHint != null || rememberMeUsername != null) {
            if (loginHint != null) {
                formData.add("username", loginHint);
            } else {
                formData.add("username", rememberMeUsername);
                formData.add("rememberMe", "on");
            }
        }

        Response challengeResponse = this.challenge(context, formData);
        context.challenge(challengeResponse);
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();
        if (formData.size() > 0) {
            forms.setFormData(formData);
        }

        return forms.createLoginUsernamePassword();
    }

    @Override
//    public void action(AuthenticationFlowContext authenticationFlowContext) {
//
//    }
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
        } else if (this.validateForm(context, formData)) {
            context.success();
        }
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
//    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
//        return false;
//    }
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

    }

    @Override
    public void close() {

    }
}
