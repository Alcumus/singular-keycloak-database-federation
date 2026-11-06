package org.opensingular.dbuserprovider.persistence;

import org.apache.commons.codec.digest.DigestUtils;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensingular.dbuserprovider.DBUserStorageException;
import org.opensingular.dbuserprovider.model.QueryConfigurations;

import javax.sql.DataSource;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLSyntaxErrorException;
import java.sql.SQLTimeoutException;
import java.sql.SQLTransientConnectionException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class UserRepositoryTest {

    private static final String CORRECT_PASSWORD = "correct-horse-battery";
    private static final String WRONG_PASSWORD   = "wrong-password-value";

    private static JdbcDataSource h2;

    @BeforeClass
    public static void setUpDatabase() throws Exception {
        h2 = new JdbcDataSource();
        h2.setURL("jdbc:h2:mem:userrepo;DB_CLOSE_DELAY=-1");
        try (Connection c = h2.getConnection(); Statement s = c.createStatement()) {
            s.execute("create table if not exists users (id varchar(36), username varchar(100), email varchar(100), hash_pwd varchar(100))");
            s.execute("delete from users");
            s.execute("insert into users values ('42', 'alice', 'alice@example.com', '" + DigestUtils.sha1Hex(CORRECT_PASSWORD) + "')");
        }
    }

    @AfterClass
    public static void tearDownDatabase() throws Exception {
        try (Connection c = h2.getConnection(); Statement s = c.createStatement()) {
            s.execute("drop all objects");
        }
    }

    private static QueryConfigurations queryConfigurations() {
        return new QueryConfigurations(
                "select count(*) from users",
                "select id as \"id\", username as \"username\", email as \"email\" from users",
                "select id as \"id\", username as \"username\", email as \"email\" from users where id = ?",
                "select id as \"id\", username as \"username\", email as \"email\" from users where username = ?",
                "select id as \"id\", username as \"username\", email as \"email\" from users where username like ?",
                "select hash_pwd from users where username = ?",
                "SHA-1",
                RDBMS.POSTGRESQL,
                false,
                false
        );
    }

    private static UserRepository repository(DataSource dataSource) {
        return new UserRepository(new FixedDataSourceProvider(dataSource), queryConfigurations());
    }

    private static UserRepository repositoryWithBrokenSql() {
        QueryConfigurations broken = new QueryConfigurations(
                "select count(*) from users",
                "select id from users",
                "select id from users where id = ?",
                "selekt id frum userz were username = ?",
                "select id from users where username like ?",
                "select hash_pwd from users where username = ?",
                "SHA-1",
                RDBMS.POSTGRESQL,
                false,
                false
        );
        return new UserRepository(new FixedDataSourceProvider(h2), broken);
    }

    // --- successful queries that find nothing must keep returning empty/null results ---

    @Test
    public void userNotFoundReturnsEmptyResultWithoutException() {
        UserRepository repository = repository(h2);

        Assert.assertFalse(repository.findUserByUsername("no-such-user").isPresent());
        Assert.assertNull(repository.findUserById("no-such-id"));
        Assert.assertTrue(repository.findUsers("no-such-user", null).isEmpty());
    }

    @Test
    public void foundUserIsReturnedNormally() {
        UserRepository repository = repository(h2);

        Optional<Map<String, String>> user = repository.findUserByUsername("alice");
        Assert.assertTrue(user.isPresent());
        Assert.assertEquals("42", user.get().get("id"));
        Assert.assertEquals(1, repository.getUsersCount(null));
    }

    // --- invalid credentials stay a boolean result, not an exception ---

    @Test
    public void invalidPasswordReturnsFalseWithoutException() {
        UserRepository repository = repository(h2);

        Assert.assertFalse(repository.validateCredentials("alice", WRONG_PASSWORD));
        Assert.assertTrue(repository.validateCredentials("alice", CORRECT_PASSWORD));
        // unknown user compares against empty hash and must also just be false
        Assert.assertFalse(repository.validateCredentials("no-such-user", WRONG_PASSWORD));
    }

    // --- infrastructure failures must surface as DBUserStorageException, never as empty results ---

    @Test
    public void connectionFailureThrowsInsteadOfReturningEmpty() {
        UserRepository repository = repository(new FailingDataSource(() -> new SQLException("connection refused", "08001", 0)));

        DBUserStorageException e = expectFailure(() -> repository.findUserByUsername("alice"));
        Assert.assertTrue(e.getCause() instanceof SQLException);
        Assert.assertEquals("08001", ((SQLException) e.getCause()).getSQLState());
    }

    @Test
    public void queryTimeoutThrowsInsteadOfReturningEmpty() {
        UserRepository repository = repository(new FailingDataSource(() -> new SQLTimeoutException("statement timed out")));

        DBUserStorageException e = expectFailure(() -> repository.getUsersCount(null));
        Assert.assertTrue(e.getCause() instanceof SQLTimeoutException);
    }

    @Test
    public void malformedSqlThrowsInsteadOfReturningEmpty() {
        UserRepository repository = repositoryWithBrokenSql();

        DBUserStorageException e = expectFailure(() -> repository.findUserByUsername("alice"));
        Assert.assertTrue(e.getCause() instanceof SQLSyntaxErrorException);
        // our exception message carries operational context but no SQL text
        Assert.assertTrue(e.getMessage().contains("find user by username"));
        Assert.assertFalse(e.getMessage().contains("selekt"));
    }

    @Test
    public void poolExhaustionThrowsInsteadOfReturningEmpty() {
        UserRepository repository = repository(new FailingDataSource(
                () -> new SQLTransientConnectionException("pool - connection is not available, request timed out")));

        DBUserStorageException e = expectFailure(() -> repository.validateCredentials("alice", CORRECT_PASSWORD));
        Assert.assertTrue(e.getCause() instanceof SQLTransientConnectionException);
    }

    // --- failure logging must not leak SQL text, passwords or user data ---

    @Test
    public void failureLogsContainNoSqlPasswordsOrUserData() {
        Logger julLogger = Logger.getLogger(UserRepository.class.getName());
        CapturingHandler handler = new CapturingHandler();
        julLogger.addHandler(handler);
        try {
            UserRepository repository = repository(new FailingDataSource(() -> new SQLException(
                    "failure while executing select hash_pwd from users", "08006", 0)));
            expectFailure(() -> repository.validateCredentials("alice", CORRECT_PASSWORD));

            String logged = handler.allMessages();
            Assert.assertFalse("log must not contain the password", logged.contains(CORRECT_PASSWORD));
            Assert.assertFalse("log must not contain the username", logged.contains("alice"));
            Assert.assertFalse("log must not contain SQL text", logged.toLowerCase().contains("select"));
            Assert.assertTrue("log must contain the operation", logged.contains("find password hash"));
            Assert.assertTrue("log must contain the sql state", logged.contains("08006"));
        } finally {
            julLogger.removeHandler(handler);
        }
    }

    private static DBUserStorageException expectFailure(Runnable call) {
        try {
            call.run();
        } catch (DBUserStorageException e) {
            return e;
        }
        throw new AssertionError("expected DBUserStorageException");
    }

    private static final class FixedDataSourceProvider extends DataSourceProvider {
        private final DataSource dataSource;

        private FixedDataSourceProvider(DataSource dataSource) {
            this.dataSource = dataSource;
        }

        @Override
        synchronized Optional<DataSource> getDataSource() {
            return Optional.of(dataSource);
        }
    }

    private static final class FailingDataSource implements DataSource {
        private final Supplier<SQLException> failure;

        private FailingDataSource(Supplier<SQLException> failure) {
            this.failure = failure;
        }

        @Override
        public Connection getConnection() throws SQLException {
            throw failure.get();
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            throw failure.get();
        }

        @Override
        public PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) {
        }

        @Override
        public void setLoginTimeout(int seconds) {
        }

        @Override
        public int getLoginTimeout() {
            return 0;
        }

        @Override
        public Logger getParentLogger() {
            return Logger.getLogger("test");
        }

        @Override
        public <T> T unwrap(Class<T> iface) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) {
            return false;
        }
    }

    private static final class CapturingHandler extends Handler {
        private final List<LogRecord> records = new ArrayList<>();
        private final SimpleFormatter formatter = new SimpleFormatter();

        @Override
        public synchronized void publish(LogRecord record) {
            records.add(record);
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }

        synchronized String allMessages() {
            StringBuilder sb = new StringBuilder();
            for (LogRecord record : records) {
                sb.append(formatter.formatMessage(record)).append('\n');
            }
            return sb.toString();
        }
    }
}
