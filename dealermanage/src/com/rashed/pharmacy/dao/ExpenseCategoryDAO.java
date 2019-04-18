package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.rashed.pharmacy.model.ExpenseCategory;
import com.rashed.pharmacy.util.*;

public class ExpenseCategoryDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public ExpenseCategoryDAO(){
		//con  = DbUtil.getConnection();
	}
	
	
	public void save(ExpenseCategory ec){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO expense_category(category_id, category_name, description, created, updated) values (?, ?, ?, ?, ?)");
	    	
			ps.setString(1, ec.getCategory_id());
			ps.setString(2, ec.getCategory_name());
			ps.setString(3, ec.getDescription());
			ps.setString(4, ec.getCreated());
			ps.setString(5, ec.getUpdated());
			
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
	
	public void delete(String category_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM expense_category WHERE category_id=?");
			
			ps.setString(1, category_id);
			
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
	
	public void update(ExpenseCategory ec){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE expense_category set category_name=?, description=?, created=?, updated=? where category_id=?");
			
			ps.setString(1, ec.getCategory_name());
			ps.setString(2, ec.getDescription());
			ps.setString(3, ec.getCreated());
			ps.setString(4, ec.getUpdated());
			ps.setString(5, ec.getCategory_id());
			
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
	
	public List<ExpenseCategory> getAllExpenseCategory(){
		List<ExpenseCategory> list = new ArrayList<ExpenseCategory>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT category_id, category_name, description, created, updated FROM expense_category");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				ExpenseCategory ec = new ExpenseCategory();
				
				ec.setCategory_id(rs.getString(1));
				ec.setCategory_name(rs.getString(2));
				ec.setDescription(rs.getString(3));
				ec.setCreated(rs.getString(4));
				ec.setUpdated(rs.getString(5));
				
				list.add(ec);				
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
	
	public ExpenseCategory getExpenseCategoryById(String category_id){
		ExpenseCategory ec = new ExpenseCategory();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT category_id, category_name, description, created, updated FROM expense_category where category_id=?");
			
			ps.setString(1, category_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				ec.setCategory_id(rs.getString(1));
				ec.setCategory_name(rs.getString(2));
				ec.setDescription(rs.getString(3));
				ec.setCreated(rs.getString(4));
				ec.setUpdated(rs.getString(5));
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

		return ec;
	}
	
	// generated auto increment id during add [S]
	public ExpenseCategory getExpenseCategoryID(){
		ExpenseCategory ec = new ExpenseCategory();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT category_id FROM expense_category");
			rs = ps.executeQuery();
			
			int category_id = 0;
			
			if(rs.next() == false) {
				category_id = 1000000;
				category_id = category_id+1;
				ec.setCategory_id("EXPNCAT" + String.valueOf(category_id));
			} else {
				if(rs.last()) {
					String strExpenseCategory = rs.getString("category_id");
					category_id = Integer.parseInt(strExpenseCategory.replaceAll("[^0-9]", ""));
					category_id = category_id+1;
					ec.setCategory_id("EXPNCAT" + String.valueOf(category_id));
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
		
		return ec;
	}
	// generated auto increment id during add [E]

}
