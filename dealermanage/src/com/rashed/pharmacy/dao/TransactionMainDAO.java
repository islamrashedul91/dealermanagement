package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.rashed.pharmacy.model.Product;

import com.rashed.pharmacy.model.TransactionMain;
import com.rashed.pharmacy.dao.PurchaseProductDAO;
import com.rashed.pharmacy.dao.PurchaseMainDAO;
import com.rashed.pharmacy.util.*;

public class TransactionMainDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	private PurchaseProductDAO ppdao;
	private PurchaseMainDAO pmdao;
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public TransactionMainDAO(){
		//con  = DbUtil.getConnection();
		ppdao = new PurchaseProductDAO();
		pmdao = new PurchaseMainDAO();
	}
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public void delete(String transaction_id){
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM transaction_main WHERE transaction_id=?");
			
			ps.setString(1, transaction_id);
			
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
	
	public List<TransactionMain> getAllTransactionMain(){
		
		List<TransactionMain> list = new ArrayList<TransactionMain>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_id, purchase_id, purchase_type, date_time, owner_id, owner_name, mobile, needed_date_time, from_account_id, to_account_id, company_id, company_name, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason FROM transaction_main ORDER BY created DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				TransactionMain tm = new TransactionMain();				
				
				tm.setTransaction_id(rs.getString(1));
				tm.setPurchase_id(rs.getString(2));
				tm.setPurchase_type(rs.getString(3));
				tm.setDate_time(rs.getString(4));
				tm.setOwner_id(rs.getString(5));
				tm.setOwner_name(rs.getString(6));
				tm.setMobile(rs.getString(7));
				tm.setNeeded_date_time(rs.getString(8));
				tm.setFrom_account_id(rs.getString(9));
				tm.setTo_account_id(rs.getString(10));
				tm.setCompany_id(rs.getString(11));
				tm.setCompany_name(rs.getString(12));
				tm.setTotal_amount(rs.getDouble(13));
				tm.setOrder_status(rs.getString(14));
				tm.setDelivery_status(rs.getString(15));
				tm.setCreated(rs.getString(16));
				tm.setUpdated(rs.getString(17));
				tm.setCreated_by(rs.getString(18));
				tm.setUpdated_by(rs.getString(19));
				tm.setReason(rs.getString(20));
			
				list.add(tm);				
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
	
	public TransactionMain getTransactionMainById(String transaction_id){
		
		TransactionMain tm = new TransactionMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_id, purchase_id, purchase_type, date_time, owner_id, owner_name, mobile, needed_date_time, from_account_id, to_account_id, company_id, company_name, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason FROM transaction_main where transaction_id=?");
			
			ps.setString(1, transaction_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				tm.setTransaction_id(rs.getString(1));
				tm.setPurchase_id(rs.getString(2));
				tm.setPurchase_type(rs.getString(3));
				tm.setDate_time(rs.getString(4));
				tm.setOwner_id(rs.getString(5));
				tm.setOwner_name(rs.getString(6));
				tm.setMobile(rs.getString(7));
				tm.setNeeded_date_time(rs.getString(8));
				tm.setFrom_account_id(rs.getString(9));
				tm.setTo_account_id(rs.getString(10));
				tm.setCompany_id(rs.getString(11));
				tm.setCompany_name(rs.getString(12));
				tm.setTotal_amount(rs.getDouble(13));
				tm.setOrder_status(rs.getString(14));
				tm.setDelivery_status(rs.getString(15));
				tm.setCreated(rs.getString(16));
				tm.setUpdated(rs.getString(17));
				tm.setCreated_by(rs.getString(18));
				tm.setUpdated_by(rs.getString(19));
				tm.setReason(rs.getString(20));
				
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

		return tm;
	}
	
	public TransactionMain getTransactionMainByIdDateTime(String purchase_id, String date_time){
		
		TransactionMain tm = new TransactionMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_id, purchase_id, purchase_type, date_time, owner_id, owner_name, mobile, needed_date_time, from_account_id, to_account_id, company_id, company_name, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason FROM transaction_main where purchase_id=? and date_time=?");
			
			ps.setString(1, purchase_id);
			ps.setString(2, date_time);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				tm.setTransaction_id(rs.getString(1));
				tm.setPurchase_id(rs.getString(2));
				tm.setPurchase_type(rs.getString(3));
				tm.setDate_time(rs.getString(4));
				tm.setOwner_id(rs.getString(5));
				tm.setOwner_name(rs.getString(6));
				tm.setMobile(rs.getString(7));
				tm.setNeeded_date_time(rs.getString(8));
				tm.setFrom_account_id(rs.getString(9));
				tm.setTo_account_id(rs.getString(10));
				tm.setCompany_id(rs.getString(11));
				tm.setCompany_name(rs.getString(12));
				tm.setTotal_amount(rs.getDouble(13));
				tm.setOrder_status(rs.getString(14));
				tm.setDelivery_status(rs.getString(15));
				tm.setCreated(rs.getString(16));
				tm.setUpdated(rs.getString(17));
				tm.setCreated_by(rs.getString(18));
				tm.setUpdated_by(rs.getString(19));
				tm.setReason(rs.getString(20));
				
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

		return tm;
	}
	
	// generated auto increment id during add [S]
	public TransactionMain getTransactionMainID(){
		
		TransactionMain tm = new TransactionMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_id FROM transaction_main");
			
			rs = ps.executeQuery();
			
			int transaction_id = 0;
			
			if(rs.next() == false) {
				transaction_id = 1000000000;
				transaction_id = transaction_id+1;
				tm.setTransaction_id("TRNX" + String.valueOf(transaction_id));
			} else {
				if(rs.last()) {
					String strTransactionMain = rs.getString("transaction_id");
					transaction_id = Integer.parseInt(strTransactionMain.replaceAll("[^0-9]", ""));
					transaction_id = transaction_id+1;
					tm.setTransaction_id("TRNX" + String.valueOf(transaction_id));
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
		
		return tm;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public TransactionMain getSelectedOtherID(String transaction_id){
		
		TransactionMain tm = new TransactionMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_id, purchase_id, date_time, owner_id, company_id, order_status, delivery_status, total_amount FROM transaction_main WHERE transaction_id=?");
			
			ps.setString(1, transaction_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strTransactionMain = rs.getString("transaction_id");
				String strPurchase = rs.getString("purchase_id");
				String strDateTime = rs.getString("date_time");
				String strOwner = rs.getString("owner_id");
				String strCompany = rs.getString("company_id");
				double dubleTotalAmount = rs.getDouble("total_amount");
				String strOrderStatus = rs.getString("order_status");
				String strDeliveryStatus = rs.getString("delivery_status");
				
				tm.setTransaction_id(strTransactionMain);
				tm.setPurchase_id(strPurchase);
				tm.setDate_time(strDateTime);
				tm.setOwner_id(strOwner);
				tm.setCompany_id(strCompany);
				tm.setTotal_amount(dubleTotalAmount);
				tm.setOrder_status(strOrderStatus);
				tm.setDelivery_status(strDeliveryStatus);
				
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
		
		return tm;
	}
	// selected other respective id during update [E]
	
	// after cancel/deliveryReturn record copy from purchase to transaction [S]
	public void purchaseMainToTransactionMain(String purchase_id, String date_time){
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO transaction_main(transaction_id, purchase_id, purchase_type, date_time, owner_id, owner_name, mobile, needed_date_time, from_account_id, to_account_id, company_id, company_name, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			// generated auto increment id during insertion [S]					
			TransactionMainDAO tmdao = new TransactionMainDAO();
			ps.setString(1, tmdao.getTransactionMainID().getTransaction_id());
			// generated auto increment id during insertion [E]
			ps.setString(2, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getPurchase_id());
			ps.setString(3, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getPurchase_type());
			ps.setString(4, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getDate_time());
			ps.setString(5, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getOwner_id());
			ps.setString(6, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getOwner_name());
			ps.setString(7, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getMobile());
			ps.setString(8, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getNeeded_date_time());
			ps.setString(9, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getFrom_account_id());
			ps.setString(10, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getTo_account_id());
			ps.setString(11, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getCompany_id());
			ps.setString(12, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getCompany_name());
			ps.setDouble(13, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getTotal_amount());
			ps.setString(14, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getOrder_status());
			ps.setString(15, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getDelivery_status());
			ps.setString(16, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getCreated());
			ps.setString(17, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getUpdated());
			ps.setString(18, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getCreated_by());
			ps.setString(19, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getUpdated_by());
			ps.setString(20, "");
			
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
	
	public void returnTotalAmount(String purchase_id, String date_time){
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE transaction_main set total_amount=?, updated=? where purchase_id=? and date_time=?");
			
			TransactionMainDAO tmdao = new TransactionMainDAO();
			
			ps.setDouble(1, (tmdao.getTransactionMainByIdDateTime(purchase_id, date_time).getTotal_amount() + ppdao.sumTotalAmountBasedOnReturnStatus(purchase_id, date_time).getTotal_amount()));
			ps.setString(2, strDate);
			ps.setString(3, purchase_id);
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
	// after cancel/deliveryReturn record copy from purchase to transaction [E]
	
	// from purchase product screen after cancel/deliveryReturn record copy from purchase to transaction [S]
	public void productPurchaseMainToTransactionMain(String purchase_id, String date_time){
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO transaction_main(transaction_id, purchase_id, purchase_type, date_time, owner_id, owner_name, mobile, needed_date_time, from_account_id, to_account_id, company_id, company_name, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			// generated auto increment id during insertion [S]
			TransactionMainDAO tmdao = new TransactionMainDAO();
			ps.setString(1, tmdao.getTransactionMainID().getTransaction_id());
			// generated auto increment id during insertion [E]
			ps.setString(2, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getPurchase_id());
			ps.setString(3, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getPurchase_type());
			ps.setString(4, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getDate_time());
			ps.setString(5, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getOwner_id());
			ps.setString(6, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getOwner_name());
			ps.setString(7, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getMobile());
			ps.setString(8, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getNeeded_date_time());
			ps.setString(9, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getFrom_account_id());
			ps.setString(10, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getTo_account_id());
			ps.setString(11, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getCompany_id());
			ps.setString(12, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getCompany_name());
			//ps.setDouble(13, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getTotal_amount());
			ps.setDouble(13, ppdao.sumTotalAmountBasedOnReturnStatus(purchase_id, date_time).getTotal_amount());
			ps.setString(14, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getOrder_status());
			//ps.setString(15, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getDelivery_status());
			ps.setString(15, "R");
			ps.setString(16, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getCreated());
			ps.setString(17, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getUpdated());
			ps.setString(18, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getCreated_by());
			ps.setString(19, pmdao.getPurchaseMainByIdDateTime(purchase_id, date_time).getUpdated_by());
			ps.setString(20, "");
			
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
	// from purchase product screen after cancel/deliveryReturn record copy from purchase to transaction [E]

}
