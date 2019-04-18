package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.rashed.pharmacy.model.Account;
import com.rashed.pharmacy.util.*;

public class AccountDAO {
	
	private Connection con;
	private static Connection conn;
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public AccountDAO(){
		//con  = DbUtil.getConnection();
	}
	
	
	public void save(Account a){
		
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO account(account_id, account_type, account_name, description, previous_balance, current_balance, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO account(account_id, account_type, account_name, description, previous_balance, current_balance, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, a.getAccount_id());
			ps.setString(2, a.getAccount_type());
			ps.setString(3, a.getAccount_name());
			ps.setString(4, a.getDescription());
			ps.setDouble(5, a.getPrevious_balance());
			ps.setDouble(6, a.getCurrent_balance());
			ps.setString(7, a.getCreated());
			ps.setString(8, a.getUpdated());
			
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
	
	public void delete(String account_id){
		
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM account WHERE account_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM account WHERE account_id=?");
			
			ps.setString(1, account_id);
			
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
	
	public void balanceUpdate(String account_id, double doubleTotalAmount){
		
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE account set previous_balance=?, current_balance=?, updated=? where account_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE account set previous_balance=?, current_balance=?, updated=? where account_id=?");
			
			AccountDAO ad = new AccountDAO();
			double doublePreviousBalance = ad.getAccountById(account_id).getPrevious_balance();
			double doubleCurrentBalance = ad.getAccountById(account_id).getCurrent_balance();
			
			double balanceHas = doubleCurrentBalance + doubleTotalAmount;
			
			ps.setDouble(1, doubleCurrentBalance);
			ps.setDouble(2, balanceHas);
			ps.setString(3, strDate);
			ps.setString(4, account_id);
			
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
	
	public void purchaseBalanceUpdate(String account_id, double doubleTotalAmount, String strCurrentDateTime){
	//public void purchaseBalanceUpdate(String account_id, double doubleTotalAmount){
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE account set previous_balance=?, current_balance=?, updated=? where account_id=?");
			
			AccountDAO ad = new AccountDAO();
			double doublePreviousBalance = ad.getAccountById(account_id).getPrevious_balance();
			double doubleCurrentBalance = ad.getAccountById(account_id).getCurrent_balance();
			
			double balanceHas = doubleCurrentBalance - doubleTotalAmount;
			
			ps.setDouble(1, doubleCurrentBalance);
			ps.setDouble(2, balanceHas);
			ps.setString(3, strCurrentDateTime);
			//ps.setString(3, strDate);
			ps.setString(4, account_id);
			
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
	
	/*public void returnBalanceUpdate(String account_id, double doubleTotalAmount){
		try{
			PreparedStatement ps = con.prepareStatement("UPDATE account set previous_balance=?, current_balance=?, updated=? where account_id=?");
			
			AccountDAO ad = new AccountDAO();
			double doublePreviousBalance = ad.getAccountById(account_id).getPrevious_balance();
			double doubleCurrentBalance = ad.getAccountById(account_id).getCurrent_balance();
			
			double balanceHas = doubleCurrentBalance - doubleTotalAmount;
			
			ps.setDouble(1, doubleCurrentBalance);
			ps.setDouble(2, balanceHas);
			ps.setString(3, strDate);
			ps.setString(4, account_id);
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		}
	}*/
	
	public void update(Account a){
		
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE account set account_type, account_name, description, previous_balance, current_balance, created, updated=? where account_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE account set account_type=?, account_name=?, description=?, previous_balance=?, current_balance=?, created=?, updated=? where account_id=?");
			
			ps.setString(1, a.getAccount_type());
			ps.setString(2, a.getAccount_name());
			ps.setString(3, a.getDescription());
			ps.setDouble(4, a.getPrevious_balance());
			ps.setDouble(5, a.getCurrent_balance());
			ps.setString(6, a.getCreated());
			ps.setString(7, a.getUpdated());
			ps.setString(8, a.getAccount_id());
			
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
	
	public List<Account> getAllAccount(){
		
		List<Account> list = new ArrayList<Account>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT account_id, account_type, account_name, description, previous_balance, current_balance, created, updated FROM account");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT account_id, account_type, account_name, description, previous_balance, current_balance, created, updated FROM account");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				Account a = new Account();				
				
				a.setAccount_id(rs.getString(1));
				a.setAccount_type(rs.getString(2));
				a.setAccount_name(rs.getString(3));
				a.setDescription(rs.getString(4));
				a.setPrevious_balance(rs.getDouble(5));
				a.setCurrent_balance(rs.getDouble(6));
				a.setCreated(rs.getString(7));
				a.setUpdated(rs.getString(8));
				
				list.add(a);				
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
	
	public Account getAccountById(String account_id){
		
		Account a = new Account();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT account_id, account_type, account_name, description, previous_balance, current_balance, created, updated FROM account where account_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT account_id, account_type, account_name, description, previous_balance, current_balance, created, updated FROM account where account_id=?");
			
			ps.setString(1, account_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				a.setAccount_id(rs.getString(1));
				a.setAccount_type(rs.getString(2));
				a.setAccount_name(rs.getString(3));
				a.setDescription(rs.getString(4));
				a.setPrevious_balance(rs.getDouble(5));
				a.setCurrent_balance(rs.getDouble(6));
				a.setCreated(rs.getString(7));
				a.setUpdated(rs.getString(8));
				
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

		return a;
	}
	
	// generated auto increment id during add [S]
	public Account getAccountID(){
		
		Account a = new Account();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT account_id FROM account");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT account_id FROM account");
			rs = ps.executeQuery();
			
			int account_id = 0;
			
			if(rs.next() == false) {
				account_id = 1000000000;
				account_id = account_id+1;
				a.setAccount_id("ACCT" + String.valueOf(account_id));
			} else {
				if(rs.last()) {
					String strAccount = rs.getString("account_id");
					account_id = Integer.parseInt(strAccount.replaceAll("[^0-9]", ""));
					account_id = account_id+1;
					a.setAccount_id("ACCT" + String.valueOf(account_id));
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
		
		return a;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public Account getSelectedOtherID(String account_id){
		
		Account a = new Account();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT account_id, previous_balance, current_balance FROM account WHERE account_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT account_id, previous_balance, current_balance FROM account WHERE account_id=?");
			
			ps.setString(1, account_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strAccount = rs.getString("account_id");
				double dblPreviousBalance = rs.getDouble("previous_balance");
				double dblCurrentBalance = rs.getDouble("current_balance");
				
				a.setAccount_id(strAccount);
				a.setPrevious_balance(dblPreviousBalance);
				a.setCurrent_balance(dblCurrentBalance);
				
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
		
		return a;
	}
	// selected other respective id during update [E]
	
	public Account getMainAccount(){
			
		Account a = new Account();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT account_id FROM account WHERE account_type=?");
			
			ps.setString(1, "MAIN");
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strAccount = rs.getString("account_id");
				
				a.setAccount_id(strAccount);
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
		
		return a;
	}

}
