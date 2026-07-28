package org.opensingular.dbuserprovider.model;

import lombok.extern.jbosslog.JBossLog;
import org.apache.commons.lang3.StringUtils;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@JBossLog
public class UserAdapter extends AbstractUserAdapterFederatedStorage {

    private final String keycloakId;
    private       String username;

    public UserAdapter(KeycloakSession session, RealmModel realm, ComponentModel model, Map<String, String> data, boolean allowDatabaseToOverwriteKeycloak) {
        super(session, realm, model);
        this.keycloakId = StorageId.keycloakId(model, data.get("id"));
        this.username = data.get("username");
        try {
          Map<String, List<String>> currentAttributes = new HashMap<>(super.getAttributes());
          data.entrySet().stream()
              .sorted(Comparator.comparing(Entry::getKey))
              .forEach(e -> synchronizeAttribute(currentAttributes, e, allowDatabaseToOverwriteKeycloak));
        } catch(Exception e) {
          log.errorv(e, "UserAdapter constructor, username={0}", this.username);
        }
    }

    private void synchronizeAttribute(Map<String, List<String>> currentAttributes, Entry<String, String> entry, boolean allowDatabaseToOverwriteKeycloak) {
        List<String> existingValues = normalizeValues(currentAttributes.get(entry.getKey()));
        List<String> newValues = mergeValues(existingValues, entry.getValue(), allowDatabaseToOverwriteKeycloak);
        if (!existingValues.equals(newValues)) {
            this.setAttribute(entry.getKey(), newValues);
            currentAttributes.put(entry.getKey(), newValues);
        }
    }

    private List<String> mergeValues(List<String> existingValues, String databaseValue, boolean allowDatabaseToOverwriteKeycloak) {
        Set<String> mergedValues = new LinkedHashSet<>();
        if (!allowDatabaseToOverwriteKeycloak) {
            mergedValues.addAll(existingValues);
        }
        String normalizedDatabaseValue = StringUtils.trimToNull(databaseValue);
        if (normalizedDatabaseValue != null) {
            mergedValues.add(normalizedDatabaseValue);
        }
        return new ArrayList<>(mergedValues);
    }

    private List<String> normalizeValues(List<String> values) {
        if (values == null || values.isEmpty()) {
            return Collections.emptyList();
        }
        return values.stream().filter(Objects::nonNull).collect(Collectors.toList());
    }


    @Override
    public String getId() {
        return keycloakId;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public void setUsername(String username) {
        this.username = username;
    }


}
