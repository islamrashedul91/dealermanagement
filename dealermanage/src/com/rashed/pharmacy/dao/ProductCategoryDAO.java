package com.rashed.pharmacy.dao;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.rashed.pharmacy.model.ProductCategory;
import com.rashed.pharmacy.util.*;

public class ProductCategoryDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public ProductCategoryDAO(){
		//con  = DbUtil.getConnection();
	}
	
	
	public void save(ProductCategory pc){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO product_category(product_category_id, product_category_name, description, created, updated) values (?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO product_category(product_category_id, product_category_name, description, created, updated) values (?, ?, ?, ?, ?)");
	    	
			ps.setString(1, pc.getProduct_category_id());
			ps.setString(2, pc.getProduct_category_name());
			ps.setString(3, pc.getDescription());
			ps.setString(4, pc.getCreated());
			ps.setString(5, pc.getUpdated());
			
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
	
	public void delete(String product_category_id){
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM product_category WHERE product_category_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM product_category WHERE product_category_id=?");
			
			ps.setString(1, product_category_id);
			
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
	
	public void update(ProductCategory pc){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE product_category set product_category_name=?, description=?, created=?, updated=? where product_category_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE product_category set product_category_name=?, description=?, created=?, updated=? where product_category_id=?");
			
			ps.setString(1, pc.getProduct_category_name());
			ps.setString(2, pc.getDescription());
			ps.setString(3, pc.getCreated());
			ps.setString(4, pc.getUpdated());
			ps.setString(5, pc.getProduct_category_id());
			
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
	
	public List<ProductCategory> getAllProductCategory(){
		List<ProductCategory> list = new ArrayList<ProductCategory>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT product_category_id, product_category_name, description, created, updated FROM product_category");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT product_category_id, product_category_name, description, created, updated FROM product_category");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				ProductCategory pc = new ProductCategory();
				
				pc.setProduct_category_id(rs.getString(1));
				pc.setProduct_category_name(rs.getString(2));
				pc.setDescription(rs.getString(3));
				pc.setCreated(rs.getString(4));
				pc.setUpdated(rs.getString(5));
				
				list.add(pc);				
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
	
	public ProductCategory getProductCategoryById(String product_category_id){
		ProductCategory pc = new ProductCategory();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT product_category_id, product_category_name, description, created, updated FROM product_category where product_category_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT product_category_id, product_category_name, description, created, updated FROM product_category where product_category_id=?");
			
			ps.setString(1, product_category_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				pc.setProduct_category_id(rs.getString(1));
				pc.setProduct_category_name(rs.getString(2));
				pc.setDescription(rs.getString(3));
				pc.setCreated(rs.getString(4));
				pc.setUpdated(rs.getString(5));
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

		return pc;
	}
	
	// generated auto increment id during add [S]
	public ProductCategory getProductCategoryID(){
		ProductCategory pc = new ProductCategory();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT product_category_id FROM product_category");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT product_category_id FROM product_category");
			rs = ps.executeQuery();
			
			int product_category_id = 0;
			
			if(rs.next() == false) {
				product_category_id = 1000000;
				product_category_id = product_category_id+1;
				pc.setProduct_category_id("PRODCAT" + String.valueOf(product_category_id));
			} else {
				if(rs.last()) {
					/*System.out.println("1111111"+product_category_id);
					product_category_id = rs.getInt("product_category_id")+1;
					System.out.println("2222222"+product_category_id);
					pc.setProduct_category_id(String.valueOf(product_category_id));*/
					
					String strProdCat = rs.getString("product_category_id");
					product_category_id = Integer.parseInt(strProdCat.replaceAll("[^0-9]", ""));
					product_category_id = product_category_id+1;
					pc.setProduct_category_id("PRODCAT" + String.valueOf(product_category_id));
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
		
		return pc;
	}
	// generated auto increment id during add [E]

}
