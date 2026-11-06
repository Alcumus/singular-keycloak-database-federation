package org.opensingular.dbuserprovider;

import com.google.auto.service.AutoService;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;
import org.opensingular.dbuserprovider.model.QueryConfigurations;
import org.opensingular.dbuserprovider.persistence.DataSourceProvider;
import org.opensingular.dbuserprovider.persistence.RDBMS;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@JBossLog
@AutoService(UserStorageProviderFactory.class)
public class DBUserStorageProviderFactory implements UserStorageProviderFactory<DBUserStorageProvider> {
    
    private static final String PARAMETER_PLACEHOLDER_HELP = "Use '?' as parameter placeholder character (replaced only once). ";
    private static final String DEFAULT_HELP_TEXT          = "Select to query all users you must return at least: \"id\". " +
                                                             "            \"username\"," +
                                                             "            \"email\" (optional)," +
                                                             "            \"firstName\" (optional)," +
                                                             "            \"lastName\" (optional). Any other parameter can be mapped by aliases to a realm scope";
    private static final String PARAMETER_HELP             = " The %s is passed as query parameter.";

    /**
     * Every ComponentModel property that changes runtime provider behavior. Used to build the
     * configuration fingerprint that lets each node detect config changes made on other nodes.
     */
    private static final List<String> FINGERPRINT_CONFIG_KEYS = Collections.unmodifiableList(Arrays.asList(
            "url", "user", "password", "rdbms",
            "count", "listAll", "findById", "findByUsername", "findBySearchTerm", "findPasswordHash", "hashFunction",
            "allowKeycloakDelete", "allowDatabaseToOverwriteKeycloak"));
    
    
    private final ConcurrentMap<String, ProviderConfig> providerConfigPerInstance = new ConcurrentHashMap<>();
    
    @Override
    public void init(Config.Scope config) {
    }
    
    @Override
    public void close() {
        List<ProviderConfig> providerConfigs = new ArrayList<>(providerConfigPerInstance.values());
        providerConfigPerInstance.clear();
        for (ProviderConfig providerConfig : providerConfigs) {
            providerConfig.retire();
        }
    }
    
    @Override
    public DBUserStorageProvider create(KeycloakSession session, ComponentModel model) {
        ProviderConfig providerConfig = acquireProviderConfig(model);
        try {
            return new DBUserStorageProvider(session, model, providerConfig.dataSourceProvider, providerConfig.queryConfigurations, providerConfig::release);
        } catch (RuntimeException e) {
            providerConfig.release();
            throw e;
        }
    }
    
    private ProviderConfig acquireProviderConfig(ComponentModel model) {
        String fingerprint = configFingerprint(model);
        while (true) {
            ProviderConfig providerConfig = providerConfigPerInstance.compute(model.getId(), (id, existing) -> {
                if (existing != null && existing.matchesFingerprint(fingerprint)) {
                    return existing;
                }
                // Build the replacement first: if configuration fails, the current mapping stays intact.
                ProviderConfig replacement = configure(model);
                if (existing != null) {
                    log.infov("Configuration changed for component: id={0} name={1}; retiring previous configuration", model.getId(), model.getName());
                    existing.retire();
                }
                return replacement;
            });
            if (providerConfig.tryRetain()) {
                return providerConfig;
            }
        }
    }

    /**
     * SHA-256 digest of all behavior-relevant component configuration values. Values (including the
     * database password) are only ever hashed; the plaintext is never stored, logged or exposed.
     */
    protected static String configFingerprint(ComponentModel model) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (String key : FINGERPRINT_CONFIG_KEYS) {
                digest.update(key.getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0);
                String value = model.get(key);
                if (value != null) {
                    digest.update(value.getBytes(StandardCharsets.UTF_8));
                }
                digest.update((byte) 0);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    protected ProviderConfig configure(ComponentModel model) {
        log.infov("Creating configuration for model: id={0} name={1}", model.getId(), model.getName());
        DataSourceProvider dataSourceProvider = new DataSourceProvider();
        try {
            String user = model.get("user");
            String password = model.get("password");
            String url = model.get("url");
            RDBMS rdbms = RDBMS.getByDescription(model.get("rdbms"));
            dataSourceProvider.configure(url, rdbms, user, password, model.getName());
            QueryConfigurations queryConfigurations = new QueryConfigurations(
                    model.get("count"),
                    model.get("listAll"),
                    model.get("findById"),
                    model.get("findByUsername"),
                    model.get("findBySearchTerm"),
                    model.get("findPasswordHash"),
                    model.get("hashFunction"),
                    rdbms,
                    model.get("allowKeycloakDelete", false),
                    model.get("allowDatabaseToOverwriteKeycloak", false)
            );
            return new ProviderConfig(dataSourceProvider, queryConfigurations, configFingerprint(model));
        } catch (RuntimeException e) {
            dataSourceProvider.close();
            throw e;
        }
    }
    
    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model) throws ComponentValidationException {
        // Validate with a throwaway configuration: the live map and HikariCP pool are only replaced
        // lazily by acquireProviderConfig() once a saved ComponentModel with a new fingerprint arrives.
        ProviderConfig validationConfig = null;
        try {
            validationConfig = configure(model);
        } catch (Exception e) {
            throw new ComponentValidationException(e.getMessage(), e);
        } finally {
            if (validationConfig != null) {
                validationConfig.retire();
            }
        }
    }
    
    @Override
    public String getId() {
        return "singular-db-user-provider";
    }
    
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                                           //DATABASE
                                           .property()
                                           .name("url")
                                           .label("JDBC URL")
                                           .helpText("JDBC Connection String")
                                           .type(ProviderConfigProperty.STRING_TYPE)
                                           .defaultValue("jdbc:jtds:sqlserver://server-name/database_name;instance=instance_name")
                                           .add()
                                           .property()
                                           .name("user")
                                           .label("JDBC Connection User")
                                           .helpText("JDBC Connection User")
                                           .type(ProviderConfigProperty.STRING_TYPE)
                                           .defaultValue("user")
                                           .add()
                                           .property()
                                           .name("password")
                                           .label("JDBC Connection Password")
                                           .helpText("JDBC Connection Password")
                                           .type(ProviderConfigProperty.PASSWORD)
                                           .defaultValue("password")
                                           .add()
                                           .property()
                                           .name("rdbms")
                                           .label("RDBMS")
                                           .helpText("Relational Database Management System")
                                           .type(ProviderConfigProperty.LIST_TYPE)
                                           .options(RDBMS.getAllDescriptions())
                                           .defaultValue(RDBMS.SQL_SERVER.getDesc())
                                           .add()
                                           .property()
                                           .name("allowKeycloakDelete")
                                           .label("Allow Keycloak's User Delete")
                                           .helpText("By default, clicking Delete on a user in Keycloak is not allowed.  Activate this option to allow to Delete Keycloak's version of the user (does not touch the user record in the linked RDBMS), e.g. to clear synching issues and allow the user to be synced from scratch from the RDBMS on next use, in Production or for testing.")
                                           .type(ProviderConfigProperty.BOOLEAN_TYPE)
                                           .defaultValue("false")
                                           .add()
                                           .property()
                                           .name("allowDatabaseToOverwriteKeycloak")
                                           .label("Allow DB Attributes to Overwrite Keycloak")
                                           // Technical details for the following comment: we aggregate both the existing Keycloak version and the DB version of an attribute in a Set, but since e.g. email is not a list of values on the Keycloak User, the new email is never set on it.
                                           .helpText("By default, once a user is loaded in Keycloak, its attributes (e.g. 'email') stay as they are in Keycloak even if an attribute of the same name now returns a different value through the query.  Activate this option to have all attributes set in the SQL query to always overwrite the existing user attributes in Keycloak (e.g. if Keycloak user has email 'test@test.com' but the query fetches a field named 'email' that has a value 'example@exemple.com', the Keycloak user will now have email attribute = 'example@exemple.com'). This behavior works with NO_CAHCE configuration. In case you set this flag under a cached configuration, the user attributes will be reload if: 1) the cached value is older than 500ms and 2) username or e-mail does not match cached values.")
                                           .type(ProviderConfigProperty.BOOLEAN_TYPE)
                                           .defaultValue("false")
                                           .add()
        
                                           //QUERIES
        
                                           .property()
                                           .name("count")
                                           .label("User count SQL query")
                                           .helpText("SQL query returning the total count of users")
                                           .type(ProviderConfigProperty.STRING_TYPE)
                                           .defaultValue("select count(*) from users")
                                           .add()
        
                                           .property()
                                           .name("listAll")
                                           .label("List All Users SQL query")
                                           .helpText(DEFAULT_HELP_TEXT)
                                           .type(ProviderConfigProperty.STRING_TYPE)
                                           .defaultValue("select \"id\"," +
                                                         "            \"username\"," +
                                                         "            \"email\"," +
                                                         "            \"firstName\"," +
                                                         "            \"lastName\"," +
                                                         "            \"cpf\"," +
                                                         "            \"fullName\" from users ")
                                           .add()
        
                                           .property()
                                           .name("findById")
                                           .label("Find user by id SQL query")
                                           .helpText(DEFAULT_HELP_TEXT + String.format(PARAMETER_HELP, "user id") + PARAMETER_PLACEHOLDER_HELP)
                                           .type(ProviderConfigProperty.STRING_TYPE)
                                           .defaultValue("select \"id\"," +
                                                         "            \"username\"," +
                                                         "            \"email\"," +
                                                         "            \"firstName\"," +
                                                         "            \"lastName\"," +
                                                         "            \"cpf\"," +
                                                         "            \"fullName\" from users where \"id\" = ? ")
                                           .add()
        
                                           .property()
                                           .name("findByUsername")
                                           .label("Find user by username SQL query")
                                           .helpText(DEFAULT_HELP_TEXT + String.format(PARAMETER_HELP, "user username") + PARAMETER_PLACEHOLDER_HELP)
                                           .type(ProviderConfigProperty.STRING_TYPE)
                                           .defaultValue("select \"id\"," +
                                                         "            \"username\"," +
                                                         "            \"email\"," +
                                                         "            \"firstName\"," +
                                                         "            \"lastName\"," +
                                                         "            \"cpf\"," +
                                                         "            \"fullName\" from users where \"username\" = ? ")
                                           .add()
        
                                           .property()
                                           .name("findBySearchTerm")
                                           .label("Find user by search term SQL query")
                                           .helpText(DEFAULT_HELP_TEXT + String.format(PARAMETER_HELP, "search term") + PARAMETER_PLACEHOLDER_HELP)
                                           .type(ProviderConfigProperty.STRING_TYPE)
                                           .defaultValue("select \"id\"," +
                                                         "            \"username\"," +
                                                         "            \"email\"," +
                                                         "            \"firstName\"," +
                                                         "            \"lastName\"," +
                                                         "            \"cpf\"," +
                                                         "            \"fullName\" from users where upper(\"username\") like (?)  or upper(\"email\") like (?) or upper(\"fullName\") like (?)")
                                           .add()
        
                                           .property()
                                           .name("findPasswordHash")
                                           .label("Find password hash (blowfish or hash digest hex) SQL query")
                                           .helpText(DEFAULT_HELP_TEXT + String.format(PARAMETER_HELP, "user username") + PARAMETER_PLACEHOLDER_HELP)
                                           .type(ProviderConfigProperty.STRING_TYPE)
                                           .defaultValue("select hash_pwd from users where \"username\" = ? ")
                                           .add()
                                           .property()
                                           .name("hashFunction")
                                           .label("Password hash function")
                                           .helpText("Hash type used to match passwrod (md* e sha* uses hex hash digest)")
                                           .type(ProviderConfigProperty.LIST_TYPE)
                                           .options("Blowfish (bcrypt)", "MD2", "MD5", "SHA-1", "SHA-256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHA-384", "SHA-512/224", "SHA-512/256", "SHA-512")
                                           .defaultValue("SHA-1")
                                           .add()
                                           .build();
    }
    
    protected static class ProviderConfig {
        private final DataSourceProvider  dataSourceProvider;
        private final QueryConfigurations queryConfigurations;
        private final String              configFingerprint;
        private       boolean             retired;
        private       boolean             closed;
        private       int                 activeInstances;

        ProviderConfig(DataSourceProvider dataSourceProvider, QueryConfigurations queryConfigurations, String configFingerprint) {

            this.dataSourceProvider = dataSourceProvider;
            this.queryConfigurations = queryConfigurations;
            this.configFingerprint = configFingerprint;
        }

        boolean matchesFingerprint(String fingerprint) {
            return configFingerprint.equals(fingerprint);
        }

        private synchronized boolean tryRetain() {
            if (retired || closed) {
                return false;
            }
            activeInstances++;
            return true;
        }

        private synchronized void release() {
            if (activeInstances > 0) {
                activeInstances--;
            }
            closeIfPossible();
        }

        private synchronized void retire() {
            retired = true;
            closeIfPossible();
        }

        private void closeIfPossible() {
            if (retired && activeInstances == 0 && !closed) {
                closed = true;
                dataSourceProvider.close();
            }
        }
    }
    
    
}
