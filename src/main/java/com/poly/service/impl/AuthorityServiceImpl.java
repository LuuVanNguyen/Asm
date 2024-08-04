package com.poly.service.impl;

import com.poly.dao.AuthorityDAO;
import com.poly.dao.CustomerDAO;
import com.poly.entity.Authority;
import com.poly.entity.Customers;
import com.poly.service.AuthorityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuthorityServiceImpl implements AuthorityService {
    @Autowired
    AuthorityDAO dao;
    @Autowired
    CustomerDAO acdao;

    @Override
    public List<Authority> findAuthoritiesOfAdministrators() {
        List<Customers> customers = acdao.getAdministrators();
        return dao.authoritiesOf(customers);
    }

    @Override
    public List<Authority> findAll() {
        return dao.findAll();
    }

    @Override
    public Authority create(Authority auth) {
        return dao.save(auth);
    }

    @Override
    public void delete(Integer id) {
        dao.deleteById(id);
    }

}
