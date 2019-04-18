package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.rashed.pharmacy.model.ExpenseMain;
import com.rashed.pharmacy.dao.*;

import com.rashed.pharmacy.dao.ExpenseProductDAO;

import com.rashed.pharmacy.util.*;

public class ExpenseMainDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	private ExpenseProductDAO epdao;
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public ExpenseMainDAO(){
		
		epdao = new ExpenseProductDAO();
	}
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public void save(ExpenseMain em){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO expense_main(expense_id, expense_type, date_time, owner_id, owner_name, mobile, needed_date_time, from_account_id, to_account_id, company_id, company_name, total_amount, order_status, expense_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, em.getExpense_id());
			ps.setString(2, em.getExpense_type());
			ps.setString(3, em.getDate_time());
			ps.setString(4, em.getOwner_id());
			ps.setString(5, em.getOwner_name());
			ps.setString(6, em.getMobile());
			ps.setString(7, em.getNeeded_date_time());
			ps.setString(8, em.getFrom_account_id());
			ps.setString(9, em.getTo_account_id());
			ps.setString(10, em.getCompany_id());
			ps.setString(11, em.getCompany_name());
			ps.setDouble(12, em.getTotal_amount());
			ps.setString(13, em.getOrder_status());
			ps.setString(14, em.getExpense_status());
			ps.setString(15, em.getCreated());
			ps.setString(16, em.getUpdated());
			ps.setString(17, em.getCreated_by());
			ps.setString(18, em.getUpdated_by());
			
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
	
	public void delete(String expense_id){
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM expense_main WHERE expense_id=?");
			
			ps.setString(1, expense_id);
			
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
	
	public void deleteByIdDateTime(String expense_id, String date_time){
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM expense_main WHERE expense_id=? and date_time=?");
			
			ps.setString(1, expense_id);
			ps.setString(2, date_time);
			
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
	
	public void update(ExpenseMain em){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE expense_main set expense_type=?, date_time=?, owner_id=?, owner_name=?, mobile=?, needed_date_time=?, from_account_id=?, to_account_id=?, company_id=?, company_name=?, total_amount=?, order_status=?, expense_status=?, created=?, updated=?, created_by=?, updated_by=? where expense_id=?");
			
			ps.setString(1, em.getExpense_type());
			ps.setString(2, em.getDate_time());
			ps.setString(3, em.getOwner_id());
			ps.setString(4, em.getOwner_name());
			ps.setString(5, em.getMobile());
			ps.setString(6, em.getNeeded_date_time());
			ps.setString(7, em.getFrom_account_id());
			ps.setString(8, em.getTo_account_id());
			ps.setString(9, em.getCompany_id());
			ps.setString(10, em.getCompany_name());
			ps.setDouble(11, em.getTotal_amount());
			ps.setString(12, em.getOrder_status());
			ps.setString(13, em.getExpense_status());
			ps.setString(14, em.getCreated());
			ps.setString(15, em.getUpdated());
			ps.setString(16, em.getCreated_by());
			ps.setString(17, em.getUpdated_by());
			ps.setString(18, em.getExpense_id());
			
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
	
	public void cancel(String expense_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE expense_main set order_status=?, updated=? where expense_id=?");
			
			ps.setString(1, "C");
			ps.setString(2, strDate);
			ps.setString(3, expense_id);
			
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
	
	public void approve(String expense_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE expense_main set order_status=?, updated=? where expense_id=?");
			
			ps.setString(1, "A");
			ps.setString(2, strDate);
			ps.setString(3, expense_id);
			
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
	
	public void expenseApprove(String expense_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE expense_main set expense_status=?, updated=? where expense_id=?");
			
			ps.setString(1, "A");
			ps.setString(2, strDate);
			ps.setString(3, expense_id);
			
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
	
	public void expenseCancel(String expense_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE expense_main set expense_status=?, updated=? where expense_id=?");
			
			ps.setString(1, "C");
			ps.setString(2, strDate);
			ps.setString(3, expense_id);
			
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
	
	public List<ExpenseMain> getAllExpenseMain(){
		List<ExpenseMain> list = new ArrayList<ExpenseMain>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT expense_id, expense_type, date_time, owner_id, owner_name, mobile, needed_date_time, from_account_id, to_account_id, company_id, company_name, total_amount, order_status, expense_status, created, updated, created_by, updated_by FROM expense_main ORDER BY created DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				ExpenseMain em = new ExpenseMain();				
				
				em.setExpense_id(rs.getString(1));
				em.setExpense_type(rs.getString(2));
				em.setDate_time(rs.getString(3));
				em.setOwner_id(rs.getString(4));
				em.setOwner_name(rs.getString(5));
				em.setMobile(rs.getString(6));
				em.setNeeded_date_time(rs.getString(7));
				em.setFrom_account_id(rs.getString(8));
				em.setTo_account_id(rs.getString(9));
				em.setCompany_id(rs.getString(10));
				em.setCompany_name(rs.getString(11));
				em.setTotal_amount(rs.getDouble(12));
				em.setOrder_status(rs.getString(13));
				em.setExpense_status(rs.getString(14));
				em.setCreated(rs.getString(15));
				em.setUpdated(rs.getString(16));
				em.setCreated_by(rs.getString(17));
				em.setUpdated_by(rs.getString(18));
			
				list.add(em);				
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
	
	public ExpenseMain getExpenseMainById(String expense_id){
		ExpenseMain em = new ExpenseMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT expense_id, expense_type, date_time, owner_id, owner_name, mobile, needed_date_time, from_account_id, to_account_id, company_id, company_name, total_amount, order_status, expense_status, created, updated, created_by, updated_by FROM expense_main where expense_id=?");
			
			ps.setString(1, expense_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				em.setExpense_id(rs.getString(1));
				em.setExpense_type(rs.getString(2));
				em.setDate_time(rs.getString(3));
				em.setOwner_id(rs.getString(4));
				em.setOwner_name(rs.getString(5));
				em.setMobile(rs.getString(6));
				em.setNeeded_date_time(rs.getString(7));
				em.setFrom_account_id(rs.getString(8));
				em.setTo_account_id(rs.getString(9));
				em.setCompany_id(rs.getString(10));
				em.setCompany_name(rs.getString(11));
				em.setTotal_amount(rs.getDouble(12));
				em.setOrder_status(rs.getString(13));
				em.setExpense_status(rs.getString(14));
				em.setCreated(rs.getString(15));
				em.setUpdated(rs.getString(16));
				em.setCreated_by(rs.getString(17));
				em.setUpdated_by(rs.getString(18));
				
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

		return em;
	}
	
	public ExpenseMain getExpenseMainByIdDateTime(String expense_id, String date_time){
		ExpenseMain em = new ExpenseMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT expense_id, expense_type, date_time, owner_id, owner_name, mobile, needed_date_time, from_account_id, to_account_id, company_id, company_name, total_amount, order_status, expense_status, created, updated, created_by, updated_by FROM expense_main where expense_id=? and date_time=?");
			
			ps.setString(1, expense_id);
			ps.setString(2, date_time);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				em.setExpense_id(rs.getString(1));
				em.setExpense_type(rs.getString(2));
				em.setDate_time(rs.getString(3));
				em.setOwner_id(rs.getString(4));
				em.setOwner_name(rs.getString(5));
				em.setMobile(rs.getString(6));
				em.setNeeded_date_time(rs.getString(7));
				em.setFrom_account_id(rs.getString(8));
				em.setTo_account_id(rs.getString(9));
				em.setCompany_id(rs.getString(10));
				em.setCompany_name(rs.getString(11));
				em.setTotal_amount(rs.getDouble(12));
				em.setOrder_status(rs.getString(13));
				em.setExpense_status(rs.getString(14));
				em.setCreated(rs.getString(15));
				em.setUpdated(rs.getString(16));
				em.setCreated_by(rs.getString(17));
				em.setUpdated_by(rs.getString(18));
				
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

		return em;
	}
	
	// generated auto increment id during add [S]
	public ExpenseMain getExpenseMainID(){
		ExpenseMain em = new ExpenseMain();
		// for get deleted id [S]
		PreparedStatement ps2 = null;
		ResultSet rs2 = null;
		// for get deleted id [E]
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT expense_id FROM expense_main");
			
			rs = ps.executeQuery();
			
			int expense_id = 0;
			
			if(rs.next() == false) {
				expense_id = 1000000000;
				expense_id = expense_id+1;
				em.setExpense_id("EXPN" + String.valueOf(expense_id));
			} else {
				if(rs.last()) {
					String strExpenseMain = rs.getString("expense_id");
					expense_id = Integer.parseInt(strExpenseMain.replaceAll("[^0-9]", ""));
					expense_id = expense_id+1;
					em.setExpense_id("EXPN" + String.valueOf(expense_id));
				}
			}
			// for get deleted id [S]
			/*int purchase_id2 = 0;
			ps2 = con.prepareStatement("SELECT purchase_id FROM transaction_main");
			rs2 = ps2.executeQuery();
			
			if (rs.last()) {
				String strPurchaseMain = rs.getString("purchase_id");
				purchase_id = Integer.parseInt(strPurchaseMain.replaceAll("[^0-9]", ""));
			} 
			if (rs2.last()) {
				String strPurchaseMain2 = rs2.getString("purchase_id");
				purchase_id2 = Integer.parseInt(strPurchaseMain2.replaceAll("[^0-9]", ""));
			}
			
			if((purchase_id == 0) && (purchase_id2 == 0)){
			
				purchase_id = 1000000000;
				purchase_id = purchase_id+1;
				pm.setPurchase_id("PRCH" + String.valueOf(purchase_id));
			
			} else if (purchase_id > purchase_id2) {
				String strPurchaseMain = rs.getString("purchase_id");
				purchase_id = Integer.parseInt(strPurchaseMain.replaceAll("[^0-9]", ""));
				purchase_id = purchase_id+1;
				pm.setPurchase_id("PRCH" + String.valueOf(purchase_id));
			} else if (purchase_id2 > purchase_id) {
				String strPurchaseMain2 = rs2.getString("purchase_id");
				purchase_id = Integer.parseInt(strPurchaseMain2.replaceAll("[^0-9]", ""));
				purchase_id = purchase_id+1;
				pm.setPurchase_id("PRCH" + String.valueOf(purchase_id));
			}*/ 
			// for get deleted id [E]
			
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
			if(ps2 != null){
				try {
					ps2.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs2 != null){
				try {
					rs2.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		
		return em;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public ExpenseMain getSelectedOtherID(String expense_id){
		ExpenseMain em = new ExpenseMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT expense_id, expense_type, date_time, owner_id, company_id, order_status, expense_status, total_amount, from_account_id, to_account_id FROM expense_main WHERE expense_id=?");
			
			ps.setString(1, expense_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strExpenseMain = rs.getString("expense_id");
				String strExpenseType = rs.getString("expense_type");
				String strDateTime = rs.getString("date_time");
				String strOwner = rs.getString("owner_id");
				String strCompany = rs.getString("company_id");
				double dubleTotalAmount = rs.getDouble("total_amount");
				String strFromAccount = rs.getString("from_account_id");
				String strToAccount = rs.getString("to_account_id");
				String strOrderStatus = rs.getString("order_status");
				String strExpenseStatus = rs.getString("expense_status");
				
				em.setExpense_id(strExpenseMain);
				em.setExpense_type(strExpenseType);
				em.setDate_time(strDateTime);
				em.setOwner_id(strOwner);
				em.setCompany_id(strCompany);
				em.setTotal_amount(dubleTotalAmount);
				em.setFrom_account_id(strFromAccount);
				em.setTo_account_id(strToAccount);
				em.setOrder_status(strOrderStatus);
				em.setExpense_status(strExpenseStatus);
				
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
		
		return em;
	}
	// selected other respective id during update [E]
	
	// for insert into expense_main total_amount from Expense Product sum total amount [S]
	public void sumTotalAmountEP(String expense_id, String date_time){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE expense_main set total_amount=?, updated=? where expense_id=? and date_time=?");
			
			ps.setDouble(1, epdao.sumTotalAmount(expense_id, date_time).getTotal_amount());
			ps.setString(2, strDate);
			ps.setString(3, expense_id);
			ps.setString(4, date_time);
			
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
	// for insert into expense_main total_amount from Expense Product sum total amount [E]

}