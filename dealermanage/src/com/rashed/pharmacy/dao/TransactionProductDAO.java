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
import com.rashed.pharmacy.model.CustomerTransactionProduct;

import com.rashed.pharmacy.model.TransactionProduct;
import com.rashed.pharmacy.util.*;

public class TransactionProductDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public TransactionProductDAO(){
		//con  = DbUtil.getConnection();
	}
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public void delete(String transaction_product_id){
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM transaction_product WHERE transaction_product_id=?");
			
			ps.setString(1, transaction_product_id);
			
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
	
	public List<TransactionProduct> getAllTransactionProduct(){
		
		List<TransactionProduct> list = new ArrayList<TransactionProduct>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_product_id, transaction_id, purchase_product_id, purchase_id, purchase_type, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, rate_per_piceces, rate_per_box, order_pack, order_quantity, tp_price, total_tp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason FROM transaction_product ORDER BY created DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				TransactionProduct tp = new TransactionProduct();				
				
				tp.setTransaction_product_id(rs.getString(1));
				tp.setTransaction_id(rs.getString(2));
				tp.setPurchase_product_id(rs.getString(3));
				tp.setPurchase_id(rs.getString(4));
				tp.setPurchase_type(rs.getString(5));
				tp.setDate_time(rs.getString(6));
				tp.setProduct_id(rs.getString(7));
				tp.setProduct_name(rs.getString(8));
				tp.setPack_type(rs.getString(9));
				tp.setPack_size(rs.getString(10));
				tp.setPiceces(rs.getInt(11));
				tp.setBonus_id(rs.getString(12));
				tp.setBonus_name(rs.getString(13));
				tp.setRate_per_piceces(rs.getDouble(14));
				tp.setRate_per_box(rs.getDouble(15));
				tp.setOrder_pack(rs.getString(16));
				tp.setOrder_quantity(rs.getInt(17));
				tp.setTp_price(rs.getDouble(18));
				tp.setTotal_tp_price(rs.getDouble(19));
				tp.setDiscount_amt(rs.getDouble(20));
				tp.setTotal_amount(rs.getDouble(21));
				tp.setOrder_status(rs.getString(22));
				tp.setDelivery_status(rs.getString(23));
				tp.setCreated(rs.getString(24));
				tp.setUpdated(rs.getString(25));
				tp.setCreated_by(rs.getString(26));
				tp.setUpdated_by(rs.getString(27));
				tp.setReason(rs.getString(28));
			
				list.add(tp);				
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
	
	public TransactionProduct getTransactionProductById(String transaction_product_id){
		
		TransactionProduct tp = new TransactionProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_product_id, transaction_id, purchase_product_id, purchase_id, purchase_type, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, rate_per_piceces, rate_per_box, order_pack, order_quantity, tp_price, total_tp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason FROM transaction_product where transaction_product_id=?");
			
			ps.setString(1, transaction_product_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				tp.setTransaction_product_id(rs.getString(1));
				tp.setTransaction_id(rs.getString(2));
				tp.setPurchase_product_id(rs.getString(3));
				tp.setPurchase_id(rs.getString(4));
				tp.setPurchase_type(rs.getString(5));
				tp.setDate_time(rs.getString(6));
				tp.setProduct_id(rs.getString(7));
				tp.setProduct_name(rs.getString(8));
				tp.setPack_type(rs.getString(9));
				tp.setPack_size(rs.getString(10));
				tp.setPiceces(rs.getInt(11));
				tp.setBonus_id(rs.getString(12));
				tp.setBonus_name(rs.getString(13));
				tp.setRate_per_piceces(rs.getDouble(14));
				tp.setRate_per_box(rs.getDouble(15));
				tp.setOrder_pack(rs.getString(16));
				tp.setOrder_quantity(rs.getInt(17));
				tp.setTp_price(rs.getDouble(18));
				tp.setTotal_tp_price(rs.getDouble(19));
				tp.setDiscount_amt(rs.getDouble(20));
				tp.setTotal_amount(rs.getDouble(21));
				tp.setOrder_status(rs.getString(22));
				tp.setDelivery_status(rs.getString(23));
				tp.setCreated(rs.getString(24));
				tp.setUpdated(rs.getString(25));
				tp.setCreated_by(rs.getString(26));
				tp.setUpdated_by(rs.getString(27));
				tp.setReason(rs.getString(28));
				
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

		return tp;
	}
	
	// generated auto increment id during add [S]
	public TransactionProduct getTransactionProductID(){
		
		TransactionProduct tp = new TransactionProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_product_id FROM transaction_product");
			
			rs = ps.executeQuery();
			
			int transaction_product_id = 0;
			
			if(rs.next() == false) {
				transaction_product_id = 1000000000;
				transaction_product_id = transaction_product_id+1;
				tp.setTransaction_product_id("TPDT" + String.valueOf(transaction_product_id));
			} else {
				if(rs.last()) {
					String strTransactionProduct = rs.getString("transaction_product_id");
					transaction_product_id = Integer.parseInt(strTransactionProduct.replaceAll("[^0-9]", ""));
					transaction_product_id = transaction_product_id+1;
					tp.setTransaction_product_id("TPDT" + String.valueOf(transaction_product_id));
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
		
		return tp;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public TransactionProduct getSelectedOtherID(String transaction_product_id){
		
		TransactionProduct tp = new TransactionProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_product_id, purchase_id, purchase_product_id, product_id, bonus_id, order_status, order_quantity FROM transaction_product WHERE transaction_product_id=?");
			
			ps.setString(1, transaction_product_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strTransactionProduct = rs.getString("transaction_product_id");
				String strTransactionMain = rs.getString("transaction_id");
				String strPurchaseProduct = rs.getString("purchase_product_id");
				String strProduct = rs.getString("product_id");
				String strBonus = rs.getString("bonus_id");
				String strOrderStatus = rs.getString("order_status");
				int intOrderQuantity = rs.getInt("order_quantity");
				
				tp.setTransaction_product_id(strTransactionProduct);
				tp.setTransaction_id(strTransactionMain);
				tp.setPurchase_product_id(strPurchaseProduct);
				tp.setProduct_id(strProduct);
				tp.setBonus_id(strBonus);
				tp.setOrder_status(strOrderStatus);
				tp.setOrder_quantity(intOrderQuantity);
				
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
		
		return tp;
	}
	// selected other respective id during update [E]
	
	public List<TransactionProduct> getAllTransactionProductByMainIdDateTime(String transaction_id, String purchase_id, String strDateTime){
		
		List<TransactionProduct> list = new ArrayList<TransactionProduct>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_product_id, transaction_id, purchase_product_id, purchase_id, purchase_type, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, rate_per_piceces, rate_per_box, order_pack, order_quantity, tp_price, total_tp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason FROM transaction_product where transaction_id=? and purchase_id=? and date_time=?");
			
			ps.setString(1, transaction_id);
			ps.setString(2, purchase_id);
			ps.setString(3, strDateTime);
			
			rs = ps.executeQuery();
			
			while (rs.next()) {
				TransactionProduct tp = new TransactionProduct();				
				
				tp.setTransaction_product_id(rs.getString(1));
				tp.setTransaction_id(rs.getString(2));
				tp.setPurchase_product_id(rs.getString(3));
				tp.setPurchase_id(rs.getString(4));
				tp.setPurchase_type(rs.getString(5));
				tp.setDate_time(rs.getString(6));
				tp.setProduct_id(rs.getString(7));
				tp.setProduct_name(rs.getString(8));
				tp.setPack_type(rs.getString(9));
				tp.setPack_size(rs.getString(10));
				tp.setPiceces(rs.getInt(11));
				tp.setBonus_id(rs.getString(12));
				tp.setBonus_name(rs.getString(13));
				tp.setRate_per_piceces(rs.getDouble(14));
				tp.setRate_per_box(rs.getDouble(15));
				tp.setOrder_pack(rs.getString(16));
				tp.setOrder_quantity(rs.getInt(17));
				tp.setTp_price(rs.getDouble(18));
				tp.setTotal_tp_price(rs.getDouble(19));
				tp.setDiscount_amt(rs.getDouble(20));
				tp.setTotal_amount(rs.getDouble(21));
				tp.setOrder_status(rs.getString(22));
				tp.setDelivery_status(rs.getString(23));
				tp.setCreated(rs.getString(24));
				tp.setUpdated(rs.getString(25));
				tp.setCreated_by(rs.getString(26));
				tp.setUpdated_by(rs.getString(27));
				tp.setReason(rs.getString(28));
			
				list.add(tp);				
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
	
	// for Requisition Product sum total amount [S]
	public TransactionProduct sumTotalAmount(String transaction_id, String purchase_id, String date_time){
		
		TransactionProduct tp = new TransactionProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sum(total_amount) FROM transaction_product where transaction_id=? and purchase_id=? and date_time=?");
			
			ps.setString(1, transaction_id);
			ps.setString(2, purchase_id);
			ps.setString(3, date_time);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if (rs.next()) {
				tp.setTotal_amount(rs.getDouble(1));
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
		
		return tp;
	}
	// for Requisition Product sum total amount [E]
	
	// after cancel/delivery  return insert into customer_transaction_product one by one from a list based on sales_product id and date time [S]	
	public void purchaseProductToTransactionProduct(String strPurchaseProductId, String strPurchaseId, String strType, String strDateTime, String strProductId,
												String strProductName, String strPackType,String strPackSize, int intPieces, String strBonusId,
												String strBonusName, double ratePerPieces, double ratePerBox, String strOrderPack, int intOrderQuantity,
												double tpPrice, double doubleTotalTpPrice, double doubleDiscount, double doubleTotalAmount, 
												String strOrderStatus, String strDeliveryStatus, String strCreated, String strUpdated,
												String strCreatedBy, String strUpdatedBy){
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO transaction_product(transaction_product_id, transaction_id, purchase_product_id, purchase_id, purchase_type, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, rate_per_piceces, rate_per_box, order_pack, order_quantity, tp_price, total_tp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			TransactionMainDAO tmdao = new TransactionMainDAO();
			
			TransactionProductDAO tpdao = new TransactionProductDAO();
			
			ps.setString(1, tpdao.getTransactionProductID().getTransaction_product_id());
			ps.setString(2, tmdao.getTransactionMainByIdDateTime(strPurchaseId, strDateTime).getTransaction_id());
			ps.setString(3, strPurchaseProductId);
			ps.setString(4, strPurchaseId);
			ps.setString(5, strType);
			ps.setString(6, strDateTime);
			ps.setString(7, strProductId);
			ps.setString(8, strProductName);
			ps.setString(9, strPackType);
			ps.setString(10, strPackSize);
			ps.setInt(11, intPieces);
			ps.setString(12, strBonusId);
			ps.setString(13, strBonusName);
			ps.setDouble(14, ratePerPieces);
			ps.setDouble(15, ratePerBox);
			ps.setString(16, strOrderPack);
			ps.setInt(17, intOrderQuantity);
			ps.setDouble(18, tpPrice);
			ps.setDouble(19, doubleTotalTpPrice);
			ps.setDouble(20, doubleDiscount);
			ps.setDouble(21, doubleTotalAmount);
			ps.setString(22, strOrderStatus);
			ps.setString(23, strDeliveryStatus);
			ps.setString(24, strCreated);
			ps.setString(25, strUpdated);
			ps.setString(26, strCreatedBy);
			ps.setString(27, strUpdatedBy);
			ps.setString(28, "");
			
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
	// after cancel/delivery return insert into customer_transaction_product one by one from a list based on sales_product id and date time [E]
	
}
