package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.rashed.pharmacy.model.Brand;
import com.rashed.pharmacy.util.*;

public class BrandDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public BrandDAO(){
		//con  = DbUtil.getConnection();
	}
	
	
	public void save(Brand b){
		
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO brand(brand_id, brand_name, product_category_id, generic_id, generic_name, created, updated, company_id, company_name) values (?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO brand(brand_id, brand_name, product_category_id, generic_id, generic_name, created, updated, company_id, company_name) values (?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, b.getBrand_id());
			ps.setString(2, b.getBrand_name());
			ps.setString(3, b.getProduct_category_id());
			ps.setString(4, b.getGeneric_id());
			ps.setString(5, b.getGeneric_name());
			ps.setString(6, b.getCreated());
			ps.setString(7, b.getUpdated());
			ps.setString(8, b.getCompany_id());
			ps.setString(9, b.getCompany_name());
			
			ps.executeUpdate();
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void delete(String brand_id){
		
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM brand WHERE brand_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM brand WHERE brand_id=?");
			
			ps.setString(1, brand_id);
			
			ps.executeUpdate();
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void update(Brand b){
		
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE brand set brand_name=?, product_category_id=?, generic_id=?, generic_name=?, created=?, updated=?, company_id=?, company_name=? where brand_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE brand set brand_name=?, product_category_id=?, generic_id=?, generic_name=?, created=?, updated=?, company_id=?, company_name=? where brand_id=?");
			
			ps.setString(1, b.getBrand_name());
			ps.setString(2, b.getProduct_category_id());
			ps.setString(3, b.getGeneric_id());
			ps.setString(4, b.getGeneric_name());
			ps.setString(5, b.getCreated());
			ps.setString(6, b.getUpdated());
			ps.setString(7, b.getCompany_id());
			ps.setString(8, b.getCompany_name());
			ps.setString(9, b.getBrand_id());
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public List<Brand> getAllBrand(){
		
		List<Brand> list = new ArrayList<Brand>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT brand_id, brand_name, product_category_id, generic_id, generic_name, created, updated, company_id, company_name FROM brand");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT brand_id, brand_name, product_category_id, generic_id, generic_name, created, updated, company_id, company_name FROM brand");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				Brand b = new Brand();				
				
				b.setBrand_id(rs.getString(1));
				b.setBrand_name(rs.getString(2));
				b.setProduct_category_id(rs.getString(3));
				b.setGeneric_id(rs.getString(4));
				b.setGeneric_name(rs.getString(5));
				b.setCreated(rs.getString(6));
				b.setUpdated(rs.getString(7));
				b.setCompany_id(rs.getString(8));
				b.setCompany_name(rs.getString(9));
				
				list.add(b);				
			}
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		
		return list;
	}
	
	public Brand getBrandById(String brand_id){
		
		Brand b = new Brand();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT brand_id, brand_name, product_category_id, generic_id, generic_name, created, updated, company_id, company_name FROM brand where brand_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT brand_id, brand_name, product_category_id, generic_id, generic_name, created, updated, company_id, company_name FROM brand where brand_id=?");
			
			ps.setString(1, brand_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				b.setBrand_id(rs.getString(1));
				b.setBrand_name(rs.getString(2));
				b.setProduct_category_id(rs.getString(3));
				b.setGeneric_id(rs.getString(4));
				b.setGeneric_name(rs.getString(5));
				b.setCreated(rs.getString(6));
				b.setUpdated(rs.getString(7));
				b.setCompany_id(rs.getString(8));
				b.setCompany_name(rs.getString(9));
			}
		} catch (Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}

		return b;
	}
	
	// generated auto increment id during add [S]
	public Brand getBrandID(){
		
		Brand b = new Brand();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT brand_id FROM brand");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT brand_id FROM brand");
			rs = ps.executeQuery();
			
			int brand_id = 0;
			
			if(rs.next() == false) {
				brand_id = 1000000000;
				brand_id = brand_id+1;
				b.setBrand_id("BRND" + String.valueOf(brand_id));
			} else {
				if(rs.last()) {
					String strBrand = rs.getString("brand_id");
					brand_id = Integer.parseInt(strBrand.replaceAll("[^0-9]", ""));
					brand_id = brand_id+1;
					b.setBrand_id("BRND" + String.valueOf(brand_id));
				}
			}
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		
		return b;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public Brand getSelectedOtherID(String brand_id){
		
		Brand b = new Brand();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT brand_id, company_id, product_category_id, generic_id FROM brand WHERE brand_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT brand_id, company_id, product_category_id, generic_id FROM brand WHERE brand_id=?");
			
			ps.setString(1, brand_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strBrand = rs.getString("brand_id");
				String strCompany = rs.getString("company_id");
				String strProductCategory = rs.getString("product_category_id");
				String strGeneric = rs.getString("generic_id");
				
				b.setBrand_id(strBrand);
				b.setCompany_id(strCompany);
				b.setProduct_category_id(strProductCategory);
				b.setGeneric_id(strGeneric);
				
			}
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		
		return b;
	}
	// selected other respective id during update [E]

}
