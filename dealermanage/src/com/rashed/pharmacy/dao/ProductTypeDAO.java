package com.rashed.pharmacy.dao;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.rashed.pharmacy.model.ProductType;
import com.rashed.pharmacy.util.*;

public class ProductTypeDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public ProductTypeDAO(){
		//con  = DbUtil.getConnection();
	}
	
	
	public void save(ProductType pt){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO product_type(product_type_id, product_type, stength, created, updated) values (?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO product_type(product_type_id, product_type, stength, created, updated) values (?, ?, ?, ?, ?)");
	    	
			ps.setString(1, pt.getProduct_type_id());
			ps.setString(2, pt.getProduct_type());
			ps.setString(3, pt.getStength());
			ps.setString(4, pt.getCreated());
			ps.setString(5, pt.getUpdated());
			
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
			//PreparedStatement ps = con.prepareStatement("DELETE FROM product_type WHERE product_type_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM product_type WHERE product_type_id=?");
			
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
	
	public void update(ProductType pt){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE product_type set product_type=?, stength=?, created=?, updated=? where product_type_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE product_type set product_type=?, stength=?, created=?, updated=? where product_type_id=?");
			
			ps.setString(1, pt.getProduct_type());
			ps.setString(2, pt.getStength());
			ps.setString(3, pt.getCreated());
			ps.setString(4, pt.getUpdated());
			ps.setString(5, pt.getProduct_type_id());
			
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
	
	public List<ProductType> getAllProductType(){
		List<ProductType> list = new ArrayList<ProductType>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT product_type_id, product_type, stength, created, updated FROM product_type");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT product_type_id, product_type, stength, created, updated FROM product_type");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				ProductType pt = new ProductType();
				
				pt.setProduct_type_id(rs.getString(1));
				pt.setProduct_type(rs.getString(2));
				pt.setStength(rs.getString(3));
				pt.setCreated(rs.getString(4));
				pt.setUpdated(rs.getString(5));
				
				list.add(pt);				
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
	
	public ProductType getProductTypeById(String product_type_id){
		ProductType pt = new ProductType();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT product_type_id, product_type, stength, created, updated FROM product_type where product_type_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT product_type_id, product_type, stength, created, updated FROM product_type where product_type_id=?");
			
			ps.setString(1, product_type_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				pt.setProduct_type_id(rs.getString(1));
				pt.setProduct_type(rs.getString(2));
				pt.setStength(rs.getString(3));
				pt.setCreated(rs.getString(4));
				pt.setUpdated(rs.getString(5));
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

		return pt;
	}
	
	// generated auto increment id during add [S]
	public ProductType getProductTypeID(){
		ProductType pt = new ProductType();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT product_type_id FROM product_type");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT product_type_id FROM product_type");
			rs = ps.executeQuery();
			
			int product_type_id = 0;
			
			if(rs.next() == false) {
				product_type_id = 1000000;
				product_type_id = product_type_id+1;
				pt.setProduct_type_id("PRDTYPE" + String.valueOf(product_type_id));
			} else {
				if(rs.last()) {
					String strProdType = rs.getString("product_type_id");
					product_type_id = Integer.parseInt(strProdType.replaceAll("[^0-9]", ""));
					product_type_id = product_type_id+1;
					pt.setProduct_type_id("PRDTYPE" + String.valueOf(product_type_id));
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
		
		return pt;
	}
	// generated auto increment id during add [E]

}
