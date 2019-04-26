package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.rashed.pharmacy.model.RequisitionMulti;
import com.rashed.pharmacy.model.SalesRate;
import com.rashed.pharmacy.util.*;

public class SalesRateDAO {
	
	private Connection con;
	private static Connection conn;
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public SalesRateDAO(){
	}
	
	
	public void save(SalesRate sr){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO sales_rate(sales_rate_id, rate_percent, description, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?)");
	    	
			ps.setString(1, sr.getSales_rate_id());
			ps.setDouble(2, sr.getRate_percent());
			ps.setString(3, sr.getDescription());
			ps.setString(4, sr.getCreated());
			ps.setString(5, sr.getUpdated());
			ps.setString(6, sr.getCreated_by());
			ps.setString(7, sr.getUpdated_by());
			
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
	
	public void delete(String sales_rate_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM sales_rate WHERE sales_rate_id=?");
			
			ps.setString(1, sales_rate_id);
			
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
	
	public void update(SalesRate sr){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales_rate set rate_percent=?, description=?, created=?, updated=?, created_by=?, updated_by=? where sales_rate_id=?");
			
			ps.setDouble(1, sr.getRate_percent());
			ps.setString(2, sr.getDescription());
			ps.setString(3, sr.getCreated());
			ps.setString(4, sr.getUpdated());
			ps.setString(5, sr.getCreated_by());
			ps.setString(6, sr.getUpdated_by());
			ps.setString(7, sr.getSales_rate_id());
			
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
	
	public List<SalesRate> getAllSalesRate(){
		List<SalesRate> list = new ArrayList<SalesRate>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_rate_id, rate_percent, description, created, updated, created_by, updated_by FROM sales_rate");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				SalesRate sr = new SalesRate();
				
				sr.setSales_rate_id(rs.getString(1));
				sr.setRate_percent(rs.getDouble(2));
				sr.setDescription(rs.getString(3));
				sr.setCreated(rs.getString(4));
				sr.setUpdated(rs.getString(5));
				sr.setCreated_by(rs.getString(6));
				sr.setUpdated_by(rs.getString(7));
				
				list.add(sr);				
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
	
	public SalesRate getSalesRateById(String sales_rate_id){
		SalesRate sr = new SalesRate();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_rate_id, rate_percent, description, created, updated, created_by, updated_by FROM sales_rate where sales_rate_id=?");
			
			ps.setString(1, sales_rate_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				sr.setSales_rate_id(rs.getString(1));
				sr.setRate_percent(rs.getDouble(2));
				sr.setDescription(rs.getString(3));
				sr.setCreated(rs.getString(4));
				sr.setUpdated(rs.getString(5));
				sr.setCreated_by(rs.getString(6));
				sr.setUpdated_by(rs.getString(7));
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

		return sr;
	}
	
	// generated auto increment id during add [S]
	public SalesRate getSalesRateID(){
		SalesRate sr = new SalesRate();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_rate_id FROM sales_rate");
			rs = ps.executeQuery();
			
			int sales_rate_id = 0;
			
			if(rs.next() == false) {
				sales_rate_id = 10000;
				sales_rate_id = sales_rate_id+1;
				sr.setSales_rate_id("SalesRate" + String.valueOf(sales_rate_id));
			} else {
				if(rs.last()) {
					String strSalesRate = rs.getString("sales_rate_id");
					sales_rate_id = Integer.parseInt(strSalesRate.replaceAll("[^0-9]", ""));
					sales_rate_id = sales_rate_id+1;
					sr.setSales_rate_id("SalesRate" + String.valueOf(sales_rate_id));
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
		
		return sr;
	}
	// generated auto increment id during add [E]
	
	public SalesRate getSelectedOtherID(){
		SalesRate sr = new SalesRate();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_rate_id, rate_percent FROM sales_rate");
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strSalesRate = rs.getString("sales_rate_id");
				double ratePercent = rs.getDouble("rate_percent");
				
				sr.setSales_rate_id(strSalesRate);
				sr.setRate_percent(ratePercent);
				
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
		
		return sr;
	}

}