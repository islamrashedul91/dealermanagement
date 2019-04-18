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
import com.rashed.pharmacy.model.RequisitionProduct;
import com.rashed.pharmacy.dao.RequisitionProductDAO;
import com.rashed.pharmacy.model.SalesProduct;
import com.rashed.pharmacy.model.CustomerPurchaseProduct;
import com.rashed.pharmacy.util.*;

public class CustomerPurchaseProductDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public CustomerPurchaseProductDAO(){
		//con  = DbUtil.getConnection();
	}
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public void save(CustomerPurchaseProduct cpp){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO customer_purchase_product(purchase_product_id, purchase_id, purchase_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, cpp.getPurchase_product_id());
			ps.setString(2, cpp.getPurchase_id());
			ps.setString(3, cpp.getPurchase_type());
			ps.setString(4, cpp.getRequisition_product_id());
			ps.setString(5, cpp.getRequisition_id());
			ps.setString(6, cpp.getDate_time());
			ps.setString(7, cpp.getProduct_id());
			ps.setString(8, cpp.getProduct_name());
			ps.setString(9, cpp.getPack_type());
			ps.setString(10, cpp.getPack_size());
			ps.setInt(11, cpp.getPiceces());
			ps.setString(12, cpp.getBonus_id());
			ps.setString(13, cpp.getBonus_name());
			ps.setString(14, cpp.getOrder_pack());
			ps.setInt(15, cpp.getOrder_quantity());
			ps.setDouble(16, cpp.getMrp_price());
			ps.setDouble(17, cpp.getTotal_mrp_price());
			ps.setDouble(18, cpp.getDiscount_amt());
			ps.setDouble(19, cpp.getTotal_amount());
			ps.setString(20, cpp.getOrder_status());
			ps.setString(21, cpp.getDelivery_status());
			ps.setString(22, cpp.getCreated());
			ps.setString(23, cpp.getUpdated());
			ps.setString(24, cpp.getCreated_by());
			ps.setString(25, cpp.getUpdated_by());
			
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
	
	public void delete(String purchase_product_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM customer_purchase_product WHERE purchase_product_id=?");
			
			ps.setString(1, purchase_product_id);
			
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
	
	public void update(CustomerPurchaseProduct cpp){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE customer_purchase_product set purchase_id=?, purchase_type=?, requisition_product_id=?, requisition_id=?, date_time=?, product_id=?, product_name=?, pack_type=?, pack_size=?, piceces=?, bonus_id=?, bonus_name=?, order_pack=?, order_quantity=?, mrp_price=?, total_mrp_price=?, discount_amt=?, total_amount=?, order_status=?, delivery_status=?, created=?, updated=?, created_by=?, updated_by=? where purchase_product_id=?");
			
			ps.setString(1, cpp.getPurchase_id());
			ps.setString(2, cpp.getPurchase_type());
			ps.setString(3, cpp.getRequisition_product_id());
			ps.setString(4, cpp.getRequisition_id());
			ps.setString(5, cpp.getDate_time());
			ps.setString(6, cpp.getProduct_id());
			ps.setString(7, cpp.getProduct_name());
			ps.setString(8, cpp.getPack_type());
			ps.setString(9, cpp.getPack_size());
			ps.setInt(10, cpp.getPiceces());
			ps.setString(11, cpp.getBonus_id());
			ps.setString(12, cpp.getBonus_name());
			ps.setString(13, cpp.getOrder_pack());
			ps.setInt(14, cpp.getOrder_quantity());
			ps.setDouble(15, cpp.getMrp_price());
			ps.setDouble(16, cpp.getTotal_mrp_price());
			ps.setDouble(17, cpp.getDiscount_amt());
			ps.setDouble(18, cpp.getTotal_amount());
			ps.setString(19, cpp.getOrder_status());
			ps.setString(20, cpp.getDelivery_status());
			ps.setString(21, cpp.getCreated());
			ps.setString(22, cpp.getUpdated());
			ps.setString(23, cpp.getCreated_by());
			ps.setString(24, cpp.getUpdated_by());
			ps.setString(25, cpp.getPurchase_product_id());
			
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
	
	public void cancel(String purchase_product_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE customer_purchase_product set order_status=?, updated=? where purchase_product_id=?");
			
			ps.setString(1, "C");
			ps.setString(2, strDate);
			ps.setString(3, purchase_product_id);
			
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
	
	public List<CustomerPurchaseProduct> getAllCustomerPurchaseProduct(){
		List<CustomerPurchaseProduct> list = new ArrayList<CustomerPurchaseProduct>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_product_id, purchase_id, purchase_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM customer_purchase_product ORDER BY created DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				CustomerPurchaseProduct cpp = new CustomerPurchaseProduct();				
				
				cpp.setPurchase_product_id(rs.getString(1));
				cpp.setPurchase_id(rs.getString(2));
				cpp.setPurchase_type(rs.getString(3));
				cpp.setRequisition_product_id(rs.getString(4));
				cpp.setRequisition_id(rs.getString(5));
				cpp.setDate_time(rs.getString(6));
				cpp.setProduct_id(rs.getString(7));
				cpp.setProduct_name(rs.getString(8));
				cpp.setPack_type(rs.getString(9));
				cpp.setPack_size(rs.getString(10));
				cpp.setPiceces(rs.getInt(11));
				cpp.setBonus_id(rs.getString(12));
				cpp.setBonus_name(rs.getString(13));
				cpp.setOrder_pack(rs.getString(14));
				cpp.setOrder_quantity(rs.getInt(15));
				cpp.setMrp_price(rs.getDouble(16));
				cpp.setTotal_mrp_price(rs.getDouble(17));
				cpp.setDiscount_amt(rs.getDouble(18));
				cpp.setTotal_amount(rs.getDouble(19));
				cpp.setOrder_status(rs.getString(20));
				cpp.setDelivery_status(rs.getString(21));
				cpp.setCreated(rs.getString(22));
				cpp.setUpdated(rs.getString(23));
				cpp.setCreated_by(rs.getString(24));
				cpp.setUpdated_by(rs.getString(25));
			
				list.add(cpp);				
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
	
	public CustomerPurchaseProduct getCustomerPurchaseProductById(String purchase_product_id){
		CustomerPurchaseProduct cpp = new CustomerPurchaseProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_product_id, purchase_id, purchase_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM customer_purchase_product where purchase_product_id=?");
			
			ps.setString(1, purchase_product_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				cpp.setPurchase_product_id(rs.getString(1));
				cpp.setPurchase_id(rs.getString(2));
				cpp.setPurchase_type(rs.getString(3));
				cpp.setRequisition_product_id(rs.getString(4));
				cpp.setRequisition_id(rs.getString(5));
				cpp.setDate_time(rs.getString(6));
				cpp.setProduct_id(rs.getString(7));
				cpp.setProduct_name(rs.getString(8));
				cpp.setPack_type(rs.getString(9));
				cpp.setPack_size(rs.getString(10));
				cpp.setPiceces(rs.getInt(11));
				cpp.setBonus_id(rs.getString(12));
				cpp.setBonus_name(rs.getString(13));
				cpp.setOrder_pack(rs.getString(14));
				cpp.setOrder_quantity(rs.getInt(15));
				cpp.setMrp_price(rs.getDouble(16));
				cpp.setTotal_mrp_price(rs.getDouble(17));
				cpp.setDiscount_amt(rs.getDouble(18));
				cpp.setTotal_amount(rs.getDouble(19));
				cpp.setOrder_status(rs.getString(20));
				cpp.setDelivery_status(rs.getString(21));
				cpp.setCreated(rs.getString(22));
				cpp.setUpdated(rs.getString(23));
				cpp.setCreated_by(rs.getString(24));
				cpp.setUpdated_by(rs.getString(25));
				
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

		return cpp;
	}
	
	// generated auto increment id during add [S]
	public CustomerPurchaseProduct getCustomerPurchaseProductID(){
		CustomerPurchaseProduct cpp = new CustomerPurchaseProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_product_id FROM customer_purchase_product");
			
			rs = ps.executeQuery();
			
			int purchase_product_id = 0;
			
			if(rs.next() == false) {
				purchase_product_id = 1000000000;
				purchase_product_id = purchase_product_id+1;
				cpp.setPurchase_product_id("PPDT" + String.valueOf(purchase_product_id));
			} else {
				if(rs.last()) {
					String strPurchaseProduct = rs.getString("purchase_product_id");
					purchase_product_id = Integer.parseInt(strPurchaseProduct.replaceAll("[^0-9]", ""));
					purchase_product_id = purchase_product_id+1;
					cpp.setPurchase_product_id("PPDT" + String.valueOf(purchase_product_id));
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
		
		return cpp;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public CustomerPurchaseProduct getSelectedOtherID(String purchase_product_id){
		CustomerPurchaseProduct cpp = new CustomerPurchaseProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_product_id, purchase_id, requisition_product_id, requisition_id, product_id, bonus_id, order_status, order_quantity FROM customer_purchase_product WHERE purchase_product_id=?");
			
			ps.setString(1, purchase_product_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strPurchaseProduct = rs.getString("purchase_product_id");
				String strPurchaseMain = rs.getString("purchase_id");
				String strRequisitionProduct = rs.getString("requisition_product_id");
				String strRequisition = rs.getString("requisition_id");
				String strProduct = rs.getString("product_id");
				String strBonus = rs.getString("bonus_id");
				String strOrderStatus = rs.getString("order_status");
				int intOrderQuantity = rs.getInt("order_quantity");
				
				cpp.setPurchase_product_id(strPurchaseProduct);
				cpp.setPurchase_id(strPurchaseMain);
				cpp.setRequisition_id(strRequisition);
				cpp.setProduct_id(strProduct);
				cpp.setBonus_id(strBonus);
				cpp.setOrder_status(strOrderStatus);
				cpp.setOrder_quantity(intOrderQuantity);
				
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
		
		return cpp;
	}
	// selected other respective id during update [E]
	
	public List<CustomerPurchaseProduct> getAllCustomerPurchaseProductByMainIdDateTime(String purchase_id, String requisition_id, String strDateTime){
		List<CustomerPurchaseProduct> list = new ArrayList<CustomerPurchaseProduct>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_product_id, purchase_id, purchase_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM customer_purchase_product where purchase_id=? and requisition_id=? and date_time=?");
			
			ps.setString(1, purchase_id);
			ps.setString(2, requisition_id);
			ps.setString(3, strDateTime);
			
			rs = ps.executeQuery();
			
			while (rs.next()) {
				CustomerPurchaseProduct cpp = new CustomerPurchaseProduct();				
				
				cpp.setPurchase_product_id(rs.getString(1));
				cpp.setPurchase_id(rs.getString(2));
				cpp.setPurchase_type(rs.getString(3));
				cpp.setRequisition_product_id(rs.getString(4));
				cpp.setRequisition_id(rs.getString(5));
				cpp.setDate_time(rs.getString(6));
				cpp.setProduct_id(rs.getString(7));
				cpp.setProduct_name(rs.getString(8));
				cpp.setPack_type(rs.getString(9));
				cpp.setPack_size(rs.getString(10));
				cpp.setPiceces(rs.getInt(11));
				cpp.setBonus_id(rs.getString(12));
				cpp.setBonus_name(rs.getString(13));
				cpp.setOrder_pack(rs.getString(14));
				cpp.setOrder_quantity(rs.getInt(15));
				cpp.setMrp_price(rs.getDouble(16));
				cpp.setTotal_mrp_price(rs.getDouble(17));
				cpp.setDiscount_amt(rs.getDouble(18));
				cpp.setTotal_amount(rs.getDouble(19));
				cpp.setOrder_status(rs.getString(20));
				cpp.setDelivery_status(rs.getString(21));
				cpp.setCreated(rs.getString(22));
				cpp.setUpdated(rs.getString(23));
				cpp.setCreated_by(rs.getString(24));
				cpp.setUpdated_by(rs.getString(25));
			
				list.add(cpp);				
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
	public CustomerPurchaseProduct sumTotalAmount(String purchase_id, String requisition_id, String date_time){
		CustomerPurchaseProduct cpp = new CustomerPurchaseProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sum(total_amount) FROM customer_purchase_product where purchase_id=? and requisition_id=? and date_time=?");
			
			ps.setString(1, purchase_id);
			ps.setString(2, requisition_id);
			ps.setString(3, date_time);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if (rs.next()) {
				cpp.setTotal_amount(rs.getDouble(1));
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
		
		return cpp;
	}
	// for Requisition Product sum total amount [E]
	
	// after delivery  approve insert into customer_purchase_product one by one from a list based on sales_product id and date time [E]
	public void SalesProductToCustomerPurchaseProduct(String strType, String strRequisitionProductId, String strRequisitionId, String strDateTime, String strProductId,
												String strProductName, String strPackType,String strPackSize, int intPieces, String strBonusId,
												String strBonusName, String strOrderPack, int intOrderQuantity, double doubleMrp, double doubleTotalMrp,
												double doubleDiscount, double doubleTotalAmount, String strOrderStatus, String strDeliveryStatus,
												String strCreated, String strUpdated){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO customer_purchase_product(purchase_product_id, purchase_id, purchase_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			CustomerPurchaseMainDAO cpmdao = new CustomerPurchaseMainDAO();
			
			CustomerPurchaseProductDAO cppdao = new CustomerPurchaseProductDAO();
			
			ps.setString(1, cppdao.getCustomerPurchaseProductID().getPurchase_product_id());
			ps.setString(2, cpmdao.getCustomerPurchaseMainByIdDateTime(strRequisitionId, strDateTime).getPurchase_id());
			ps.setString(3, "Requisition");
			//ps.setString(3, strType);
			ps.setString(4, strRequisitionProductId);
			ps.setString(5, strRequisitionId);
			ps.setString(6, strDateTime);
			ps.setString(7, strProductId);
			ps.setString(8, strProductName);
			ps.setString(9, strPackType);
			ps.setString(10, strPackSize);
			ps.setInt(11, intPieces);
			ps.setString(12, strBonusId);
			ps.setString(13, strBonusName);
			ps.setString(14, strOrderPack);
			ps.setInt(15, intOrderQuantity);
			ps.setDouble(16, doubleMrp);
			ps.setDouble(17, doubleTotalMrp);
			ps.setDouble(18, doubleDiscount);
			ps.setDouble(19, doubleTotalAmount);
			ps.setString(20, strOrderStatus);
			ps.setString(21, strDeliveryStatus);
			ps.setString(22, strCreated);
			ps.setString(23, strUpdated);
			ps.setString(24, "");
			ps.setString(25, "");
			
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
	// after delivery approve insert into customer_purchase_product one by one from a list based on sales_product id and date time [E]
	
}
