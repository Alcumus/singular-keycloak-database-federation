package org.opensingular.dbuserprovider.persistence;

import lombok.extern.jbosslog.JBossLog;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.NotImplementedException;
import org.mindrot.jbcrypt.BCrypt;
import org.opensingular.dbuserprovider.DBUserStorageException;
import org.opensingular.dbuserprovider.model.QueryConfigurations;
import org.opensingular.dbuserprovider.util.PagingUtil;
import org.opensingular.dbuserprovider.util.PagingUtil.Pageable;

import javax.sql.DataSource;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.function.Function;


@JBossLog
public class UserRepository {
    
    
    private DataSourceProvider  dataSourceProvider;
    private QueryConfigurations queryConfigurations;
    
    public UserRepository(DataSourceProvider dataSourceProvider, QueryConfigurations queryConfigurations) {
        this.dataSourceProvider  = dataSourceProvider;
        this.queryConfigurations = queryConfigurations;
    }
    
    
    private <T> T doQuery(String operation, String query, Pageable pageable, Function<ResultSet, T> resultTransformer, Object... params) {
        Optional<DataSource> dataSourceOpt = dataSourceProvider.getDataSource();
        if (!dataSourceOpt.isPresent()) {
            throw new DBUserStorageException("Database failure during operation [" + operation + "]: no datasource available", null);
        }
        DataSource dataSource = dataSourceOpt.get();
        try (Connection c = dataSource.getConnection()) {
            if (pageable != null) {
                query = PagingUtil.formatScriptWithPageable(query, pageable, queryConfigurations.getRDBMS());
            }
            log.debugv("Executing database operation: {0}", operation);
            try (PreparedStatement statement = c.prepareStatement(query)) {
                if (params != null) {
                    for (int i = 1; i <= params.length; i++) {
                        statement.setObject(i, params[i - 1]);
                    }
                }
                try (ResultSet rs = statement.executeQuery()) {
                    return resultTransformer.apply(rs);
                }
            }
        } catch (SQLException e) {
            // Intentionally not logging SQL text, parameters or the driver message:
            // they may contain queries, usernames, credentials or other personal data.
            log.errorv("Database operation failed: operation={0} sqlState={1} errorCode={2} exception={3}",
                       operation, e.getSQLState(), e.getErrorCode(), e.getClass().getName());
            throw new DBUserStorageException("Database failure during operation [" + operation + "]", e);
        }
    }
    
    private List<Map<String, String>> readMap(ResultSet rs) {
        try {
            List<Map<String, String>> data         = new ArrayList<>();
            Set<String>               columnsFound = new LinkedHashSet<>();
            for (int i = 1; i <= rs.getMetaData().getColumnCount(); i++) {
                String columnLabel = rs.getMetaData().getColumnLabel(i);
                columnsFound.add(columnLabel);
            }
            while (rs.next()) {
                Map<String, String> result = new LinkedHashMap<>();
                for (String col : columnsFound) {
                    result.put(col, rs.getString(col));
                }
                data.add(result);
            }
            return data;
        } catch (Exception e) {
            throw new DBUserStorageException(e.getMessage(), e);
        }
    }
    
    
    private Integer readInt(ResultSet rs) {
        try {
            return rs.next() ? rs.getInt(1) : null;
        } catch (Exception e) {
            throw new DBUserStorageException(e.getMessage(), e);
        }
    }
    
    private Boolean readBoolean(ResultSet rs) {
        try {
            return rs.next() ? rs.getBoolean(1) : null;
        } catch (Exception e) {
            throw new DBUserStorageException(e.getMessage(), e);
        }
    }
    
    private String readString(ResultSet rs) {
        try {
            return rs.next() ? rs.getString(1) : null;
        } catch (Exception e) {
            throw new DBUserStorageException(e.getMessage(), e);
        }
    }
    
    public List<Map<String, String>> getAllUsers() {
        return doQuery("list all users", queryConfigurations.getListAll(), null, this::readMap);
    }
    
    public int getUsersCount(String search) {
        if (search == null || search.isEmpty()) {
            return Optional.ofNullable(doQuery("count users", queryConfigurations.getCount(), null, this::readInt)).orElse(0);
        } else {
            String query = String.format("select count(*) from (%s) count", queryConfigurations.getFindBySearchTerm());
            return Optional.ofNullable(doQuery("count users by search term", query, null, this::readInt, search)).orElse(0);
        }
    }
    
    
    public Map<String, String> findUserById(String id) {
        return Optional.ofNullable(doQuery("find user by id", queryConfigurations.getFindById(), null, this::readMap, id))
                       .orElse(Collections.emptyList())
                       .stream().findFirst().orElse(null);
    }
    
    public Optional<Map<String, String>> findUserByUsername(String username) {
        return Optional.ofNullable(doQuery("find user by username", queryConfigurations.getFindByUsername(), null, this::readMap, username))
                       .orElse(Collections.emptyList())
                       .stream().findFirst();
    }
    
    public List<Map<String, String>> findUsers(String search, PagingUtil.Pageable pageable) {
        if (search == null || search.isEmpty()) {
            return doQuery("list users", queryConfigurations.getListAll(), pageable, this::readMap);
        }
        return doQuery("search users", queryConfigurations.getFindBySearchTerm(), pageable, this::readMap, search);
    }
    
    public boolean validateCredentials(String username, String password) {
        String hash = Optional.ofNullable(doQuery("find password hash", queryConfigurations.getFindPasswordHash(), null, this::readString, username)).orElse("");
        if (queryConfigurations.isBlowfish()) {
            return !hash.isEmpty() && BCrypt.checkpw(password, hash);
        } else {
            MessageDigest digest   = DigestUtils.getDigest(queryConfigurations.getHashFunction());
            byte[]        pwdBytes = StringUtils.getBytesUtf8(password);
            return Objects.equals(Hex.encodeHexString(digest.digest(pwdBytes)), hash);
        }
    }
    
    public boolean updateCredentials(String username, String password) {
        throw new NotImplementedException("Password update not supported");
    }
    
    public boolean removeUser() {
        return queryConfigurations.getAllowKeycloakDelete();
    }
}
