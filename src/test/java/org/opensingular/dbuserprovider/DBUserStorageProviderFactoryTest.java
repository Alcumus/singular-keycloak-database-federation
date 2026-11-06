package org.opensingular.dbuserprovider;

import org.junit.Assert;
import org.junit.Test;
import org.keycloak.component.ComponentModel;
import org.opensingular.dbuserprovider.model.QueryConfigurations;
import org.opensingular.dbuserprovider.persistence.DataSourceProvider;
import org.opensingular.dbuserprovider.persistence.RDBMS;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class DBUserStorageProviderFactoryTest {

    @Test
    public void createShouldConfigureOnlyOnceWhenCalledConcurrently() throws Exception {
        TestFactory factory = new TestFactory();
        ComponentModel model = newModel();

        int concurrency = 8;
        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<DBUserStorageProvider>> futures = new ArrayList<>();

        for (int i = 0; i < concurrency; i++) {
            futures.add(executor.submit(() -> {
                start.await();
                return factory.create(null, model);
            }));
        }

        start.countDown();

        List<DBUserStorageProvider> providers = new ArrayList<>();
        for (Future<DBUserStorageProvider> future : futures) {
            providers.add(future.get(5, TimeUnit.SECONDS));
        }

        for (DBUserStorageProvider provider : providers) {
            provider.close();
        }

        executor.shutdown();
        Assert.assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));

        factory.close();

        Assert.assertEquals(1, factory.configureCalls.get());
        Assert.assertEquals(1, factory.closedProviderConfigs.get());
    }

    @Test
    public void createShouldReuseProviderConfigWhenConfigurationUnchanged() {
        TestFactory factory = new TestFactory();
        ComponentModel model = newModel();

        DBUserStorageProvider first  = factory.create(null, model);
        DBUserStorageProvider second = factory.create(null, model);

        Assert.assertEquals(1, factory.configureCalls.get());

        first.close();
        second.close();
        Assert.assertEquals(0, factory.closedProviderConfigs.get());

        factory.close();
        Assert.assertEquals(1, factory.closedProviderConfigs.get());
    }

    @Test
    public void createShouldReplaceProviderConfigWhenConfigurationChanges() {
        // every key that changes runtime behavior must trigger a replacement
        String[] keys = {"url", "user", "password", "rdbms", "count", "listAll", "findById",
                         "findByUsername", "findBySearchTerm", "findPasswordHash", "hashFunction",
                         "allowKeycloakDelete", "allowDatabaseToOverwriteKeycloak"};
        for (String key : keys) {
            TestFactory factory = new TestFactory();
            ComponentModel model = newModel();

            DBUserStorageProvider inFlight = factory.create(null, model);

            model.put(key, "changed-value");
            DBUserStorageProvider replacedProvider = factory.create(null, model);

            Assert.assertEquals("configure call count after changing key: " + key, 2, factory.configureCalls.get());
            // in-flight user of the retired configuration can still complete
            Assert.assertEquals("premature close after changing key: " + key, 0, factory.closedProviderConfigs.get());

            inFlight.close();
            // retired datasource closes only once its last reference is released
            Assert.assertEquals("retired config not closed after changing key: " + key, 1, factory.closedProviderConfigs.get());

            replacedProvider.close();
            factory.close();
            Assert.assertEquals("live config not closed after changing key: " + key, 2, factory.closedProviderConfigs.get());
        }
    }

    @Test
    public void validateConfigurationShouldNotMutateLiveConfiguration() {
        TestFactory factory = new TestFactory();
        ComponentModel model = newModel();

        DBUserStorageProvider provider = factory.create(null, model);
        Assert.assertEquals(1, factory.configureCalls.get());

        ComponentModel candidate = newModel();
        candidate.put("url", "jdbc:test://other-host/other-db");
        factory.validateConfiguration(null, null, candidate);

        // validation built a throwaway config and closed it immediately
        Assert.assertEquals(2, factory.configureCalls.get());
        Assert.assertEquals(1, factory.closedProviderConfigs.get());

        // the live (saved) configuration is still cached and reused
        DBUserStorageProvider again = factory.create(null, model);
        Assert.assertEquals(2, factory.configureCalls.get());

        provider.close();
        again.close();
        factory.close();
        Assert.assertEquals(2, factory.closedProviderConfigs.get());
    }

    @Test
    public void concurrentCreateShouldReplaceChangedConfigurationOnlyOnce() throws Exception {
        TestFactory factory = new TestFactory();
        ComponentModel model = newModel();

        factory.create(null, model).close();
        Assert.assertEquals(1, factory.configureCalls.get());

        model.put("url", "jdbc:test://changed-host/changed-db");

        int concurrency = 8;
        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<DBUserStorageProvider>> futures = new ArrayList<>();

        for (int i = 0; i < concurrency; i++) {
            futures.add(executor.submit(() -> {
                start.await();
                return factory.create(null, model);
            }));
        }

        start.countDown();

        List<DBUserStorageProvider> providers = new ArrayList<>();
        for (Future<DBUserStorageProvider> future : futures) {
            providers.add(future.get(5, TimeUnit.SECONDS));
        }

        // one configure for the original config, exactly one for the replacement
        Assert.assertEquals(2, factory.configureCalls.get());
        // the original config (no active users) was retired and closed during replacement
        Assert.assertEquals(1, factory.closedProviderConfigs.get());

        for (DBUserStorageProvider provider : providers) {
            provider.close();
        }

        executor.shutdown();
        Assert.assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));

        factory.close();
        Assert.assertEquals(2, factory.closedProviderConfigs.get());
    }

    @Test
    public void fingerprintShouldNotExposePassword() {
        ComponentModel model = newModel();
        model.put("password", "super-secret-value");

        String fingerprint = DBUserStorageProviderFactory.configFingerprint(model);

        Assert.assertNotNull(fingerprint);
        Assert.assertTrue("fingerprint must be a SHA-256 hex digest", fingerprint.matches("[0-9a-f]{64}"));
        Assert.assertFalse("fingerprint must not contain the plaintext password",
                fingerprint.contains("super-secret-value"));
    }

    private static ComponentModel newModel() {
        ComponentModel model = new ComponentModel();
        model.setId("component-1");
        model.setName("Test Provider");
        model.put("url", "jdbc:test://localhost/db");
        model.put("user", "db-user");
        model.put("password", "db-password");
        model.put("rdbms", RDBMS.SQL_SERVER.getDesc());
        model.put("count", "select count(*) from users");
        model.put("listAll", "select * from users");
        model.put("findById", "select * from users where id = ?");
        model.put("findByUsername", "select * from users where username = ?");
        model.put("findBySearchTerm", "select * from users where username like ?");
        model.put("findPasswordHash", "select hash from users where username = ?");
        model.put("hashFunction", "SHA-1");
        model.put("allowKeycloakDelete", "false");
        model.put("allowDatabaseToOverwriteKeycloak", "false");
        return model;
    }

    private static final class TestFactory extends DBUserStorageProviderFactory {
        private final AtomicInteger configureCalls = new AtomicInteger();
        private final AtomicInteger closedProviderConfigs = new AtomicInteger();

        @Override
        protected ProviderConfig configure(ComponentModel model) {
            configureCalls.incrementAndGet();
            return new ProviderConfig(new TestDataSourceProvider(closedProviderConfigs), new QueryConfigurations(
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "SHA-1",
                    RDBMS.SQL_SERVER,
                    false,
                    false
            ), configFingerprint(model));
        }
    }

    private static final class TestDataSourceProvider extends DataSourceProvider {
        private final AtomicInteger closeCalls;
        private       boolean       closed;

        private TestDataSourceProvider(AtomicInteger closeCalls) {
            this.closeCalls = closeCalls;
        }

        @Override
        public synchronized void close() {
            if (closed) {
                return;
            }
            closed = true;
            closeCalls.incrementAndGet();
        }
    }
}