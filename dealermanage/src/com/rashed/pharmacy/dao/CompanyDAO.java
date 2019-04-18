package com.rashed.pharmacy.dao;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;




import com.rashed.pharmacy.model.Company;
import com.rashed.pharmacy.util.*;

public class CompanyDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public CompanyDAO(){
		//con  = DbUtil.getConnection();
	}
	
	
	public void save(Company c){
		
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO company(company_id, company_name, description, created, updated) values (?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO company(company_id, company_name, description, created, updated) values (?, ?, ?, ?, ?)");
	    	
			ps.setString(1, c.getCompany_id());
			ps.setString(2, c.getCompany_name());
			ps.setString(3, c.getDescription());
			ps.setString(4, c.getCreated());
			ps.setString(5, c.getUpdated());
			
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
	
	public void delete(String company_id){
		
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM company WHERE company_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM company WHERE company_id=?");
			
			ps.setString(1, company_id);
			
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
	
	public void update(Company c){
		
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE company set company_name=?, description=?, created=?, updated=? where company_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE company set company_name=?, description=?, created=?, updated=? where company_id=?");
			
			ps.setString(1, c.getCompany_name());
			ps.setString(2, c.getDescription());
			ps.setString(3, c.getCreated());
			ps.setString(4, c.getUpdated());
			ps.setString(5, c.getCompany_id());
			
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
	
	public List<Company> getAllCompany(){
		
		List<Company> list = new ArrayList<Company>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT company_id, company_name, description, created, updated FROM company");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT company_id, company_name, description, created, updated FROM company");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				Company c = new Company();
				
				c.setCompany_id(rs.getString(1));
				c.setCompany_name(rs.getString(2));
				c.setDescription(rs.getString(3));
				c.setCreated(rs.getString(4));
				c.setUpdated(rs.getString(5));
				
				list.add(c);				
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
	
	public Company getCompanyById(String company_id){
		Company c = new Company();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT company_id, company_name, description, created, updated FROM company where company_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT company_id, company_name, description, created, updated FROM company where company_id=?");
			
			ps.setString(1, company_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				c.setCompany_id(rs.getString(1));
				c.setCompany_name(rs.getString(2));
				c.setDescription(rs.getString(3));
				c.setCreated(rs.getString(4));
				c.setUpdated(rs.getString(5));
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
		

		return c;
	}
	
	// generated auto increment id during add [S]
	public Company getCompanyID(){
		Company c = new Company();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT company_id FROM company");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT company_id FROM company");
			rs = ps.executeQuery();
			
			int company_id = 0;
			
			if(rs.next() == false) {
				company_id = 1000000000;
				company_id = company_id+1;
				c.setCompany_id("COMP"+String.valueOf(company_id));
			} else {
				if(rs.last()) {
					/*System.out.println("1111111"+company_id);
					company_id = rs.getInt("company_id")+1;
					System.out.println("2222222"+company_id);
					c.setCompany_id(String.valueOf(company_id));*/
					
					String strComp = rs.getString("company_id");
					company_id = Integer.parseInt(strComp.replaceAll("[^0-9]", ""));
					company_id = company_id+1;
					//c.setCompany_id(String.valueOf(company_id));
					c.setCompany_id("COMP"+String.valueOf(company_id));
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
		
		return c;
	}
	// generated auto increment id during add [E]

}