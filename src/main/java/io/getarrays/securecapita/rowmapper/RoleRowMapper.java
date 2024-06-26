package io.getarrays.securecapita.rowmapper;

import io.getarrays.securecapita.domain.Role;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

public class RoleRowMapper implements RowMapper<Role> {
    @Override
    public Role mapRow(ResultSet rs, int rowNum) throws SQLException {
        return Role.builder()
                .id(rs.getLong("id")) // we map the id inside of the id of the row into the java object
                .name(rs.getString("name"))
                .permission(rs.getString("permission"))
                .build();
    }
}
