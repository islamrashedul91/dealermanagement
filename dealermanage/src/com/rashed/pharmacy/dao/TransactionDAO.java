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
import com.rashed.pharmacy.model.Purchase;
import com.rashed.pharmacy.model.Transaction;
import com.rashed.pharmacy.util.*;

public class TransactionDAO {
	
	private Connection con;
	private static Connection conn;
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	private PurchaseDAO phdao;
	
	public TransactionDAO(){
		//con  = DbUtil.getConnection();
		phdao = new PurchaseDAO();
	}
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public void purchaseToTransaction(String purchase_id, String action){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO transaction(transaction_id, transaction_type, reason, purchase_id, purchase_type, requisition_id, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, rate_per_piceces, rate_per_box, tp_price, total_tp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO transaction(transaction_id, transaction_type, reason, purchase_id, purchase_type, requisition_id, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, rate_per_piceces, rate_per_box, tp_price, total_tp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			// generated auto increment id during insertion [S]
			TransactionDAO td = new TransactionDAO();
			ps.setString(1, td.getTransactionID().getTransaction_id());
			// generated auto increment id during insertion [E]
			if(action.equalsIgnoreCase("purchaseReturn")){
				ps.setString(2, "Purchase");
			} else if(action.equalsIgnoreCase("cancel")){
				ps.setString(2, "Requisition");
			}
			ps.setString(3, "");
			ps.setString(4, phdao.getPurchaseById(purchase_id).getPurchase_id());
			ps.setString(5, phdao.getPurchaseById(purchase_id).getPurchase_type());
			ps.setString(6, phdao.getPurchaseById(purchase_id).getRequisition_id());
			ps.setString(7, phdao.getPurchaseById(purchase_id).getProduct_id());
			ps.setString(8, phdao.getPurchaseById(purchase_id).getProduct_name());
			ps.setString(9, phdao.getPurchaseById(purchase_id).getPack_type());
			ps.setString(10, phdao.getPurchaseById(purchase_id).getPack_size());
			ps.setInt(11, phdao.getPurchaseById(purchase_id).getPiceces());
			ps.setString(12, phdao.getPurchaseById(purchase_id).getBonus_id());
			ps.setString(13, phdao.getPurchaseById(purchase_id).getBonus_name());
			ps.setString(14, phdao.getPurchaseById(purchase_id).getOrder_pack());
			ps.setInt(15, phdao.getPurchaseById(purchase_id).getOrder_quantity());
			ps.setDouble(16, phdao.getPurchaseById(purchase_id).getRate_per_piceces());
			ps.setDouble(17, phdao.getPurchaseById(purchase_id).getRate_per_box());
			ps.setDouble(18, phdao.getPurchaseById(purchase_id).getTp_price());
			ps.setDouble(19, phdao.getPurchaseById(purchase_id).getTotal_tp_price());
			ps.setDouble(20, phdao.getPurchaseById(purchase_id).getDiscount_amt());
			ps.setDouble(21, phdao.getPurchaseById(purchase_id).getTotal_amount());
			ps.setString(22, phdao.getPurchaseById(purchase_id).getNeeded_date_time());
			ps.setString(23, phdao.getPurchaseById(purchase_id).getFrom_account_id());
			ps.setString(24, phdao.getPurchaseById(purchase_id).getTo_account_id());
			ps.setString(25, phdao.getPurchaseById(purchase_id).getOrder_status());
			ps.setString(26, phdao.getPurchaseById(purchase_id).getDelivery_status());
			ps.setString(27, phdao.getPurchaseById(purchase_id).getCreated());
			/*ps.setString(28, phdao.getPurchaseById(purchase_id).getUpdated());*/
			ps.setString(28, strDate);
			ps.setString(29, phdao.getPurchaseById(purchase_id).getCreated_by());
			ps.setString(30, phdao.getPurchaseById(purchase_id).getUpdated_by());
			
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
	
	public void delete(String transaction_id){
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM transaction WHERE transaction_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM transaction WHERE transaction_id=?");
			
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
	
	public List<Transaction> getAllTransaction(){
		List<Transaction> list = new ArrayList<Transaction>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT transaction_id, transaction_type, reason, purchase_id, purchase_type, requisition_id, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, rate_per_piceces, rate_per_box, tp_price, total_tp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, order_status, delivery_status, created, updated, created_by, updated_by FROM transaction ORDER BY created DESC");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_id, transaction_type, reason, purchase_id, purchase_type, requisition_id, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, rate_per_piceces, rate_per_box, tp_price, total_tp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, order_status, delivery_status, created, updated, created_by, updated_by FROM transaction ORDER BY created DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				Transaction t = new Transaction();				
				
				t.setTransaction_id(rs.getString(1));
				t.setTransaction_type(rs.getString(2));
				t.setReason(rs.getString(3));
				t.setPurchase_id(rs.getString(4));
				t.setPurchase_type(rs.getString(5));
				t.setRequisition_id(rs.getString(6));
				t.setProduct_id(rs.getString(7));
				t.setProduct_name(rs.getString(8));
				t.setPack_type(rs.getString(9));
				t.setPack_size(rs.getString(10));
				t.setPiceces(rs.getInt(11));
				t.setBonus_id(rs.getString(12));
				t.setBonus_name(rs.getString(13));
				t.setOrder_pack(rs.getString(14));
				t.setOrder_quantity(rs.getInt(15));
				t.setRate_per_piceces(rs.getDouble(16));
				t.setRate_per_box(rs.getDouble(17));
				t.setTp_price(rs.getDouble(18));
				t.setTotal_tp_price(rs.getDouble(19));
				t.setDiscount_amt(rs.getDouble(20));
				t.setTotal_amount(rs.getDouble(21));
				t.setNeeded_date_time(rs.getString(22));
				t.setFrom_account_id(rs.getString(23));
				t.setTo_account_id(rs.getString(24));
				t.setOrder_status(rs.getString(25));
				t.setDelivery_status(rs.getString(26));
				t.setCreated(rs.getString(27));
				t.setUpdated(rs.getString(28));
				t.setCreated_by(rs.getString(29));
				t.setUpdated_by(rs.getString(30));
			
				list.add(t);				
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
	
	public Transaction getTransactionById(String transaction_id){
		Transaction t = new Transaction();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT transaction_id, transaction_type, reason, purchase_id, purchase_type, requisition_id, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, rate_per_piceces, rate_per_box, tp_price, total_tp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, order_status, delivery_status, created, updated, created_by, updated_by FROM transaction where transaction_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_id, transaction_type, reason, purchase_id, purchase_type, requisition_id, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, rate_per_piceces, rate_per_box, tp_price, total_tp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, order_status, delivery_status, created, updated, created_by, updated_by FROM transaction where transaction_id=?");
			
			ps.setString(1, transaction_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				t.setTransaction_id(rs.getString(1));
				t.setTransaction_type(rs.getString(2));
				t.setReason(rs.getString(3));
				t.setPurchase_id(rs.getString(4));
				t.setPurchase_type(rs.getString(5));
				t.setRequisition_id(rs.getString(6));
				t.setProduct_id(rs.getString(7));
				t.setProduct_name(rs.getString(8));
				t.setPack_type(rs.getString(9));
				t.setPack_size(rs.getString(10));
				t.setPiceces(rs.getInt(11));
				t.setBonus_id(rs.getString(12));
				t.setBonus_name(rs.getString(13));
				t.setOrder_pack(rs.getString(14));
				t.setOrder_quantity(rs.getInt(15));
				t.setRate_per_piceces(rs.getDouble(16));
				t.setRate_per_box(rs.getDouble(17));
				t.setTp_price(rs.getDouble(18));
				t.setTotal_tp_price(rs.getDouble(19));
				t.setDiscount_amt(rs.getDouble(20));
				t.setTotal_amount(rs.getDouble(21));
				t.setNeeded_date_time(rs.getString(22));
				t.setFrom_account_id(rs.getString(23));
				t.setTo_account_id(rs.getString(24));
				t.setOrder_status(rs.getString(25));
				t.setDelivery_status(rs.getString(26));
				t.setCreated(rs.getString(27));
				t.setUpdated(rs.getString(28));
				t.setCreated_by(rs.getString(29));
				t.setUpdated_by(rs.getString(30));
				
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

		return t;
	}
	
	// generated auto increment id during add [S]
	public Transaction getTransactionID(){
		Transaction t = new Transaction();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT transaction_id FROM transaction");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_id FROM transaction");
			rs = ps.executeQuery();
			
			int transaction_id = 0;
			
			if(rs.next() == false) {
				transaction_id = 1000000000;
				transaction_id = transaction_id+1;
				t.setTransaction_id("TRAN" + String.valueOf(transaction_id));
			} else {
				if(rs.last()) {
					String strTransaction = rs.getString("transaction_id");
					transaction_id = Integer.parseInt(strTransaction.replaceAll("[^0-9]", ""));
					transaction_id = transaction_id+1;
					t.setTransaction_id("TRAN" + String.valueOf(transaction_id));
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
		
		return t;
	}
	// generated auto increment id during add [E]
	
}
