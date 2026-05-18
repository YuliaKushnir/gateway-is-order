package org.example.gateway.user;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserShortInfo {
    private String id;
    private String keycloakId;
    private String email;
    private String firstName;
    private String lastName;
}
