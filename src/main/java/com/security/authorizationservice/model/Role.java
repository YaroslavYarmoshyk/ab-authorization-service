package com.security.authorizationservice.model;

import com.security.authorizationservice.enumeration.RoleName;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;

@Getter
@Setter
@Entity
@Table(name = "roles")
@SQLDelete(sql = "UPDATE roles SET is_deleted = true WHERE id=?")
@SQLRestriction(value = "is_deleted <> 'true'")
public class Role extends BaseEntity {
    @Column(name = "name", nullable = false, unique = true)
    @Enumerated(value = EnumType.STRING)
    private RoleName roleName;
}
