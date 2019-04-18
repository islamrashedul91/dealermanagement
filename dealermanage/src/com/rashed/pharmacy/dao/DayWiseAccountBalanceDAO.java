package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.rashed.pharmacy.model.DayWiseAccountBalance;
import com.rashed.pharmacy.util.*;

public class DayWiseAccountBalanceDAO {
	
	private Connection con;
	private static Connection conn;
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public DayWiseAccountBalanceDAO(){
		//con  = DbUtil.getConnection();
	}
	
	
	public void save(DayWiseAccountBalance dwab){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO day_wise_account_balance(day_wise_balance_id, date_time, account_id, account_type, account_name, description, previous_balance, credit_balance, debit_balance, current_balance, day_balance, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO day_wise_account_balance(day_wise_balance_id, date_time, account_id, account_type, account_name, description, previous_balance, credit_balance, debit_balance, current_balance, day_balance, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, dwab.getDay_wise_balance_id());
			ps.setString(2, dwab.getDate_time());
			ps.setString(3, dwab.getAccount_id());
			ps.setString(4, dwab.getAccount_type());
			ps.setString(5, dwab.getAccount_name());
			ps.setString(6, dwab.getDescription());
			ps.setDouble(7, dwab.getPrevious_balance());
			ps.setDouble(8, dwab.getCredit_balance());
			ps.setDouble(9, dwab.getDebit_balance());
			ps.setDouble(10, dwab.getCurrent_balance());
			ps.setDouble(11, dwab.getDay_balance());
			ps.setString(12, dwab.getCreated());
			ps.setString(13, dwab.getUpdated());
			
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
	
	public void delete(String day_wise_balance_id){
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM day_wise_account_balance WHERE day_wise_balance_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM day_wise_account_balance WHERE day_wise_balance_id=?");
			
			ps.setString(1, day_wise_balance_id);
			
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
	
	public void dayBalance(String account_id, double salesTotalAmount, String strCurrentDateTime){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO day_wise_account_balance(day_wise_balance_id, date_time, account_id, account_type, account_name, description, previous_balance, credit_balance, debit_balance, current_balance, day_balance, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO day_wise_account_balance(day_wise_balance_id, date_time, account_id, account_type, account_name, description, previous_balance, credit_balance, debit_balance, current_balance, day_balance, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			DayWiseAccountBalanceDAO dwabDao = new DayWiseAccountBalanceDAO();
			// for get the value AccountDAO from [S]
			AccountDAO ad = new AccountDAO();
			double accountPreviousBalance = ad.getAccountById(account_id).getPrevious_balance();
			double accountCurrentBalance = ad.getAccountById(account_id).getCurrent_balance();
			String strAccountType = ad.getAccountById(account_id).getAccount_type();
			String strAccountName = ad.getAccountById(account_id).getAccount_name();
			String strDescription = ad.getAccountById(account_id).getDescription();
			// for get the value AccountDAO from [E]
			double dayWiseCurrentBalance = accountPreviousBalance + salesTotalAmount;
			double dayWiseDayBalance = dayWiseCurrentBalance;
			
			ps.setString(1, dwabDao.getDayWiseAccountBalanceID().getDay_wise_balance_id());
			ps.setString(2, strCurrentDateTime);
			ps.setString(3, account_id);
			ps.setString(4, strAccountType);
			ps.setString(5, strAccountName);
			ps.setString(6, strDescription);
			ps.setDouble(7, accountPreviousBalance);
			ps.setDouble(8, 0.00);
			ps.setDouble(9, salesTotalAmount);
			ps.setDouble(10, dayWiseCurrentBalance);
			ps.setDouble(11, dayWiseDayBalance);
			ps.setString(12, strCurrentDateTime);
			ps.setString(13, "");
			
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
	
	public void purchaseDayBalance(String account_id, double purchaseTotalAmount, String strCurrentDateTime){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO day_wise_account_balance(day_wise_balance_id, date_time, account_id, account_type, account_name, description, previous_balance, credit_balance, debit_balance, current_balance, day_balance, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO day_wise_account_balance(day_wise_balance_id, date_time, account_id, account_type, account_name, description, previous_balance, credit_balance, debit_balance, current_balance, day_balance, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			DayWiseAccountBalanceDAO dwabDao = new DayWiseAccountBalanceDAO();
			// for get the value AccountDAO from [S]
			AccountDAO ad = new AccountDAO();
			double accountPreviousBalance = ad.getAccountById(account_id).getPrevious_balance();
			double accountCurrentBalance = ad.getAccountById(account_id).getCurrent_balance();
			String strAccountType = ad.getAccountById(account_id).getAccount_type();
			String strAccountName = ad.getAccountById(account_id).getAccount_name();
			String strDescription = ad.getAccountById(account_id).getDescription();
			// for get the value AccountDAO from [E]
			double dayWiseCurrentBalance = accountPreviousBalance - purchaseTotalAmount;
			double dayWiseDayBalance = dayWiseCurrentBalance;
			
			ps.setString(1, dwabDao.getDayWiseAccountBalanceID().getDay_wise_balance_id());
			ps.setString(2, strCurrentDateTime);
			ps.setString(3, account_id);
			ps.setString(4, strAccountType);
			ps.setString(5, strAccountName);
			ps.setString(6, strDescription);
			ps.setDouble(7, accountPreviousBalance);
			ps.setDouble(8, purchaseTotalAmount);
			ps.setDouble(9, 0.00);
			ps.setDouble(10, dayWiseCurrentBalance);
			ps.setDouble(11, dayWiseDayBalance);
			ps.setString(12, strCurrentDateTime);
			ps.setString(13, "");
			
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
	
	public List<DayWiseAccountBalance> getAllDayWiseAccountBalance(){
		List<DayWiseAccountBalance> list = new ArrayList<DayWiseAccountBalance>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT day_wise_balance_id, date_time, account_id, account_type, account_name, description, previous_balance, credit_balance, debit_balance, current_balance, day_balance, created, updated FROM day_wise_account_balance");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT day_wise_balance_id, date_time, account_id, account_type, account_name, description, previous_balance, credit_balance, debit_balance, current_balance, day_balance, created, updated FROM day_wise_account_balance");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				DayWiseAccountBalance dwab = new DayWiseAccountBalance();				
				
				dwab.setDay_wise_balance_id(rs.getString(1));
				dwab.setDate_time(rs.getString(2));
				dwab.setAccount_id(rs.getString(3));
				dwab.setAccount_type(rs.getString(4));
				dwab.setAccount_name(rs.getString(5));;
				dwab.setDescription(rs.getString(6));
				dwab.setPrevious_balance(rs.getDouble(7));
				dwab.setCredit_balance(rs.getDouble(8));
				dwab.setDebit_balance(rs.getDouble(9));
				dwab.setCurrent_balance(rs.getDouble(10));
				dwab.setDay_balance(rs.getDouble(11));
				dwab.setCreated(rs.getString(12));
				dwab.setUpdated(rs.getString(13));
				
				list.add(dwab);				
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
	
	public DayWiseAccountBalance getDayWiseAccountBalanceById(String day_wise_balance_id){
		DayWiseAccountBalance dwab = new DayWiseAccountBalance();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT day_wise_balance_id, date_time, account_id, account_type, account_name, description, previous_balance, credit_balance, debit_balance, current_balance, day_balance, created, updated FROM day_wise_account_balance where day_wise_balance_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT day_wise_balance_id, date_time, account_id, account_type, account_name, description, previous_balance, credit_balance, debit_balance, current_balance, day_balance, created, updated FROM day_wise_account_balance where day_wise_balance_id=?");
			
			ps.setString(1, day_wise_balance_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				dwab.setDay_wise_balance_id(rs.getString(1));
				dwab.setDate_time(rs.getString(2));
				dwab.setAccount_id(rs.getString(3));
				dwab.setAccount_type(rs.getString(4));
				dwab.setAccount_name(rs.getString(5));;
				dwab.setDescription(rs.getString(6));
				dwab.setPrevious_balance(rs.getDouble(7));
				dwab.setCredit_balance(rs.getDouble(8));
				dwab.setDebit_balance(rs.getDouble(9));
				dwab.setCurrent_balance(rs.getDouble(10));
				dwab.setDay_balance(rs.getDouble(11));
				dwab.setCreated(rs.getString(12));
				dwab.setUpdated(rs.getString(13));
				
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

		return dwab;
	}
	
	// generated auto increment id during add [S]
	public DayWiseAccountBalance getDayWiseAccountBalanceID(){
		DayWiseAccountBalance a = new DayWiseAccountBalance();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT day_wise_balance_id FROM day_wise_account_balance");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT day_wise_balance_id FROM day_wise_account_balance");
			rs = ps.executeQuery();
			
			int day_wise_balance_id = 0;
			
			if(rs.next() == false) {
				day_wise_balance_id = 1000000000;
				day_wise_balance_id = day_wise_balance_id+1;
				a.setDay_wise_balance_id("DWAB" + String.valueOf(day_wise_balance_id));
			} else {
				if(rs.last()) {
					String strDayWiseBalance = rs.getString("day_wise_balance_id");
					day_wise_balance_id = Integer.parseInt(strDayWiseBalance.replaceAll("[^0-9]", ""));
					day_wise_balance_id = day_wise_balance_id+1;
					a.setDay_wise_balance_id("DWAB" + String.valueOf(day_wise_balance_id));
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
	public DayWiseAccountBalance getSelectedOtherID(String day_wise_balance_id){
		DayWiseAccountBalance dwab = new DayWiseAccountBalance();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT day_wise_balance_id, date_time, account_id, previous_balance, credit_balance, debit_balance, current_balance, day_balance FROM day_wise_account_balance WHERE day_wise_balance_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT day_wise_balance_id, date_time, account_id, previous_balance, credit_balance, debit_balance, current_balance, day_balance FROM day_wise_account_balance WHERE day_wise_balance_id=?");
			
			ps.setString(1, day_wise_balance_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strDayWiseBalance = rs.getString("day_wise_balance_id");
				String strDateTime = rs.getString("date_time");
				String strAccount = rs.getString("account_id");
				double dblPreviousBalance = rs.getDouble("previous_balance");
				double dblCreditBalance = rs.getDouble("credit_balance");
				double dblDebitBalance = rs.getDouble("debit_balance");
				double dblCurrentBalance = rs.getDouble("current_balance");
				double dblDayBalance = rs.getDouble("day_balance");
				
				dwab.setDay_wise_balance_id(strDayWiseBalance);
				dwab.setDate_time(strDateTime);
				dwab.setAccount_id(strAccount);
				dwab.setPrevious_balance(dblPreviousBalance);
				dwab.setCredit_balance(dblCreditBalance);
				dwab.setDebit_balance(dblDebitBalance);
				dwab.setCurrent_balance(dblCurrentBalance);
				dwab.setDay_balance(dblDayBalance);
				
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
		
		return dwab;
	}
	// selected other respective id during update [E]

}
