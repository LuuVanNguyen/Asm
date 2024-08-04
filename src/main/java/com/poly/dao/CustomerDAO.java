package com.poly.dao;

import com.poly.entity.Customers;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface CustomerDAO extends JpaRepository<Customers, String> {
    @Query("SELECT DISTINCT ar.customer FROM Authority ar WHERE ar.role.id IN('DIRE','STAF')")
    List<Customers> getAdministrators();

    @Query("SELECT a FROM Customers a WHERE a.username =?1 and a.password=?2")
    Customers getCustomer(String username, String password);

    @Query("SELECT a FROM Customers a WHERE a.email=?1")
    public Customers findByEmail(String email);

    @Query("SELECT a FROM Customers a WHERE a.token=?1")
    public Customers findByToken(String token);

}
