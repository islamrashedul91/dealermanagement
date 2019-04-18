package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.rashed.pharmacy.model.Product;
import com.rashed.pharmacy.model.RequisitionProduct;
import com.rashed.pharmacy.dao.RequisitionProductDAO;
import com.rashed.pharmacy.model.SalesProduct;
import com.rashed.pharmacy.dao.CustomerPurchaseProductDAO;
import com.rashed.pharmacy.dao.CustomerTransactionProductDAO;

import com.rashed.pharmacy.model.PurchaseProduct;
import com.rashed.pharmacy.util.*;

public class PurchaseProductDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	private ProductDAO pdao;
	private RequisitionProductDAO rpdao;
	
	private PurchaseProductDAO ppdao;
	private TransactionProductDAO tpdao;
	private ProfitLossDAO pldao;
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public PurchaseProductDAO(){
		//con  = DbUtil.getConnection();
		pdao = new ProductDAO();
	}
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	// for decimal format [S]
	DecimalFormat df = new DecimalFormat("#.##");
	// for decimal format [S]
	
	public void save(PurchaseProduct pp){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO purchase_product(purchase_product_id, purchase_id, purchase_type, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, rate_per_piceces, rate_per_box, order_pack, order_quantity, tp_price, total_tp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, pp.getPurchase_product_id());
			ps.setString(2, pp.getPurchase_id());
			ps.setString(3, pp.getPurchase_type());
			ps.setString(4, pp.getDate_time());
			ps.setString(5, pp.getProduct_id());
			ps.setString(6, pp.getProduct_name());
			ps.setString(7, pp.getPack_type());
			ps.setString(8, pp.getPack_size());
			ps.setInt(9, pp.getPiceces());
			ps.setString(10, pp.getBonus_id());
			ps.setString(11, pp.getBonus_name());
			ps.setDouble(12, pp.getRate_per_piceces());
			ps.setDouble(13, pp.getRate_per_box());
			ps.setString(14, pp.getOrder_pack());
			ps.setInt(15, pp.getOrder_quantity());
			ps.setDouble(16, pp.getTp_price());
			ps.setDouble(17, pp.getTotal_tp_price());
			ps.setDouble(18, pp.getDiscount_amt());
			ps.setDouble(19, pp.getTotal_amount());
			ps.setString(20, pp.getOrder_status());
			ps.setString(21, pp.getDelivery_status());
			ps.setString(22, pp.getCreated());
			ps.setString(23, pp.getUpdated());
			ps.setString(24, pp.getCreated_by());
			ps.setString(25, pp.getUpdated_by());
			
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
			ps = con.prepareStatement("DELETE FROM purchase_product WHERE purchase_product_id=?");
			
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
	
	public void deleteByIdDateTime(String purchase_id, String date_time){

		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM purchase_product WHERE purchase_id=? and date_time=?");
			
			ps.setString(1, purchase_id);
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
	
	// delivery return from sales product screen [S]
	public void deleteByPPIdPIdDateTime(String purchase_product_id, String purchase_id, String date_time){

		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM purchase_product WHERE purchase_product_id=? and purchase_id=? and date_time=?");
			
			ps.setString(1, purchase_product_id);
			ps.setString(2, purchase_id);
			ps.setString(3, date_time);
			
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
	// delivery return from sales product screen [E]
	
	public void update(PurchaseProduct pp){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase_product set purchase_id=?, purchase_type=?, date_time=?, product_id=?, product_name=?, pack_type=?, pack_size=?, piceces=?, bonus_id=?, bonus_name=?, rate_per_piceces=?, rate_per_box=?, order_pack=?, order_quantity=?, tp_price=?, total_tp_price=?, discount_amt=?, total_amount=?, order_status=?, delivery_status=?, created=?, updated=?, created_by=?, updated_by=? where purchase_product_id=?");
			
			ps.setString(1, pp.getPurchase_id());
			ps.setString(2, pp.getPurchase_type());
			ps.setString(3, pp.getDate_time());
			ps.setString(4, pp.getProduct_id());
			ps.setString(5, pp.getProduct_name());
			ps.setString(6, pp.getPack_type());
			ps.setString(7, pp.getPack_size());
			ps.setInt(8, pp.getPiceces());
			ps.setString(9, pp.getBonus_id());
			ps.setString(10, pp.getBonus_name());
			ps.setDouble(11, pp.getRate_per_piceces());
			ps.setDouble(12, pp.getRate_per_box());
			ps.setString(13, pp.getOrder_pack());
			ps.setInt(14, pp.getOrder_quantity());
			ps.setDouble(15, pp.getTp_price());
			ps.setDouble(16, pp.getTotal_tp_price());
			ps.setDouble(17, pp.getDiscount_amt());
			ps.setDouble(18, pp.getTotal_amount());
			ps.setString(19, pp.getOrder_status());
			ps.setString(20, pp.getDelivery_status());
			ps.setString(21, pp.getCreated());
			ps.setString(22, pp.getUpdated());
			ps.setString(23, pp.getCreated_by());
			ps.setString(24, pp.getUpdated_by());
			ps.setString(25, pp.getPurchase_product_id());
			
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
			ps = con.prepareStatement("UPDATE purchase_product set order_status=?, updated=? where purchase_product_id=?");
			
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
	
	public void approve(String purchase_product_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase_product set order_status=?, updated=? where purchase_product_id=?");
			
			ps.setString(1, "A");
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
	
	// set requisition_product order_status='A' based on requisition_multi id [S]
	public void approveByMainPurchase(String purchase_id, String date_time){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase_product set order_status=?, updated=? where purchase_id=? and date_time=?");
			
			ps.setString(1, "A");
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
	// set requisition_product order_status='A' based on requisition_multi id [E]
	
	public void deliveryApproveByMainPurchase(String purchase_id, String date_time){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase_product set delivery_status=?, updated=? where purchase_id=? and date_time=?");
			
			ps.setString(1, "D");
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
	
	public void deliveryReturn(String purchase_product_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase_product set delivery_status=?, updated=? where purchase_product_id=?");
			
			ps.setString(1, "R");
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
	
	public void deliveryReturnByMainPurchase(String purchase_id, String date_time){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase_product set delivery_status=?, updated=? where purchase_id=? and date_time=?");
			
			ps.setString(1, "R");
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
	
	// delivery return from sales product screen [S]
	public void deliveryReturnByPurchaseProduct(String purchase_product_id, String purchase_id, String date_time){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase_product set delivery_status=?, updated=? where purchase_product_id=? and purchase_id=? and date_time=?");
			
			ps.setString(1, "R");
			ps.setString(2, strDate);
			ps.setString(3, purchase_product_id);
			ps.setString(4, purchase_id);
			ps.setString(5, date_time);
			
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
	// delivery return from sales product screen [E]
	
	public List<PurchaseProduct> getAllPurchaseProduct(){
		List<PurchaseProduct> list = new ArrayList<PurchaseProduct>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_product_id, purchase_id, purchase_type, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, rate_per_piceces, rate_per_box, order_pack, order_quantity, tp_price, total_tp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM purchase_product ORDER BY created DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				PurchaseProduct pp = new PurchaseProduct();				
				
				pp.setPurchase_product_id(rs.getString(1));
				pp.setPurchase_id(rs.getString(2));
				pp.setPurchase_type(rs.getString(3));
				pp.setDate_time(rs.getString(4));
				pp.setProduct_id(rs.getString(5));
				pp.setProduct_name(rs.getString(6));
				pp.setPack_type(rs.getString(7));
				pp.setPack_size(rs.getString(8));
				pp.setPiceces(rs.getInt(9));
				pp.setBonus_id(rs.getString(10));
				pp.setBonus_name(rs.getString(11));
				pp.setRate_per_piceces(rs.getDouble(12));
				pp.setRate_per_box(rs.getDouble(13));
				pp.setOrder_pack(rs.getString(14));
				pp.setOrder_quantity(rs.getInt(15));
				pp.setTp_price(rs.getDouble(16));
				pp.setTotal_tp_price(rs.getDouble(17));
				pp.setDiscount_amt(rs.getDouble(18));
				pp.setTotal_amount(rs.getDouble(19));
				pp.setOrder_status(rs.getString(20));
				pp.setDelivery_status(rs.getString(21));
				pp.setCreated(rs.getString(22));
				pp.setUpdated(rs.getString(23));
				pp.setCreated_by(rs.getString(24));
				pp.setUpdated_by(rs.getString(25));
			
				list.add(pp);				
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
	
	public PurchaseProduct getPurchaseProductById(String purchase_product_id){
		PurchaseProduct pp = new PurchaseProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_product_id, purchase_id, purchase_type, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, rate_per_piceces, rate_per_box, order_pack, order_quantity, tp_price, total_tp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM purchase_product where purchase_product_id=?");
			
			ps.setString(1, purchase_product_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				pp.setPurchase_product_id(rs.getString(1));
				pp.setPurchase_id(rs.getString(2));
				pp.setPurchase_type(rs.getString(3));
				pp.setDate_time(rs.getString(4));
				pp.setProduct_id(rs.getString(5));
				pp.setProduct_name(rs.getString(6));
				pp.setPack_type(rs.getString(7));
				pp.setPack_size(rs.getString(8));
				pp.setPiceces(rs.getInt(9));
				pp.setBonus_id(rs.getString(10));
				pp.setBonus_name(rs.getString(11));
				pp.setRate_per_piceces(rs.getDouble(12));
				pp.setRate_per_box(rs.getDouble(13));
				pp.setOrder_pack(rs.getString(14));
				pp.setOrder_quantity(rs.getInt(15));
				pp.setTp_price(rs.getDouble(16));
				pp.setTotal_tp_price(rs.getDouble(17));
				pp.setDiscount_amt(rs.getDouble(18));
				pp.setTotal_amount(rs.getDouble(19));
				pp.setOrder_status(rs.getString(20));
				pp.setDelivery_status(rs.getString(21));
				pp.setCreated(rs.getString(22));
				pp.setUpdated(rs.getString(23));
				pp.setCreated_by(rs.getString(24));
				pp.setUpdated_by(rs.getString(25));
				
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

		return pp;
	}
	
	// generated auto increment id during add [S]
	public PurchaseProduct getPurchaseProductID(){
		PurchaseProduct pp = new PurchaseProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_product_id FROM purchase_product");
			
			rs = ps.executeQuery();
			
			int purchase_product_id = 0;
			
			if(rs.next() == false) {
				purchase_product_id = 1000000000;
				purchase_product_id = purchase_product_id+1;
				pp.setPurchase_product_id("PPDT" + String.valueOf(purchase_product_id));
			} else {
				if(rs.last()) {
					String strPurchaseProduct = rs.getString("purchase_product_id");
					purchase_product_id = Integer.parseInt(strPurchaseProduct.replaceAll("[^0-9]", ""));
					purchase_product_id = purchase_product_id+1;
					pp.setPurchase_product_id("PPDT" + String.valueOf(purchase_product_id));
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
		
		return pp;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public PurchaseProduct getSelectedOtherID(String purchase_product_id){
		PurchaseProduct pp = new PurchaseProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_product_id, purchase_id, purchase_type, date_time, product_id, bonus_id, order_status, delivery_status, order_quantity FROM purchase_product WHERE purchase_product_id=?");
			
			ps.setString(1, purchase_product_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strPurchaseProduct = rs.getString("purchase_product_id");
				String strPurchaseMain = rs.getString("purchase_id");
				String strPurchaseType = rs.getString("purchase_type");
				String strDateTime = rs.getString("date_time");
				String strProduct = rs.getString("product_id");
				String strBonus = rs.getString("bonus_id");
				String strOrderStatus = rs.getString("order_status");
				String strDeliveryStatus = rs.getString("delivery_status");
				int intOrderQuantity = rs.getInt("order_quantity");
				
				pp.setPurchase_product_id(strPurchaseProduct);
				pp.setPurchase_id(strPurchaseMain);
				pp.setPurchase_type(strPurchaseType);
				pp.setDate_time(strDateTime);
				pp.setProduct_id(strProduct);
				pp.setBonus_id(strBonus);
				pp.setOrder_status(strOrderStatus);
				pp.setDelivery_status(strDeliveryStatus);
				pp.setOrder_quantity(intOrderQuantity);
				
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
		
		return pp;
	}
	// selected other respective id during update [E]
	
	public List<PurchaseProduct> getAllPurchaseProductByMainIdDateTime(String purchase_id, String strDateTime){
		List<PurchaseProduct> list = new ArrayList<PurchaseProduct>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_product_id, purchase_id, purchase_type, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, rate_per_piceces, rate_per_box, order_pack, order_quantity, tp_price, total_tp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM purchase_product where purchase_id=? and date_time=?");
			
			ps.setString(1, purchase_id);
			ps.setString(2, strDateTime);
			
			rs = ps.executeQuery();
			
			while (rs.next()) {
				PurchaseProduct pp = new PurchaseProduct();				
				
				pp.setPurchase_product_id(rs.getString(1));
				pp.setPurchase_id(rs.getString(2));
				pp.setPurchase_type(rs.getString(3));
				pp.setDate_time(rs.getString(4));
				pp.setProduct_id(rs.getString(5));
				pp.setProduct_name(rs.getString(6));
				pp.setPack_type(rs.getString(7));
				pp.setPack_size(rs.getString(8));
				pp.setPiceces(rs.getInt(9));
				pp.setBonus_id(rs.getString(10));
				pp.setBonus_name(rs.getString(11));
				pp.setRate_per_piceces(rs.getDouble(12));
				pp.setRate_per_box(rs.getDouble(13));
				pp.setOrder_pack(rs.getString(14));
				pp.setOrder_quantity(rs.getInt(15));
				pp.setTp_price(rs.getDouble(16));
				pp.setTotal_tp_price(rs.getDouble(17));
				pp.setDiscount_amt(rs.getDouble(18));
				pp.setTotal_amount(rs.getDouble(19));
				pp.setOrder_status(rs.getString(20));
				pp.setDelivery_status(rs.getString(21));
				pp.setCreated(rs.getString(22));
				pp.setUpdated(rs.getString(23));
				pp.setCreated_by(rs.getString(24));
				pp.setUpdated_by(rs.getString(25));
			
				list.add(pp);				
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
	public PurchaseProduct sumTotalAmount(String purchase_id, String date_time){
		PurchaseProduct sp = new PurchaseProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sum(total_amount) FROM purchase_product where purchase_id=? and date_time=?");
			
			ps.setString(1, purchase_id);
			ps.setString(2, date_time);
			
			rs = ps.executeQuery();
			
			if (rs.next()) {
				sp.setTotal_amount(rs.getDouble(1));
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
		
		return sp;
	}
	// for Requisition Product sum total amount [E]
	
	// after delivery  return insert into customer_transaction_main based on sales_product id, Requisition_id and date time [S]
	public PurchaseProduct sumTotalAmountBasedOnReturnStatus(String purchase_id, String date_time){
		PurchaseProduct pp = new PurchaseProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sum(total_amount) FROM purchase_product where purchase_id=? and date_time=? and delivery_status=?");
			
			ps.setString(1, purchase_id);
			ps.setString(2, date_time);
			ps.setString(3, "R");
			
			rs = ps.executeQuery();
			
			if (rs.next()) {
				pp.setTotal_amount(rs.getDouble(1));
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
		
		return pp;
	}
	// after delivery  return insert into customer_transaction_main based on sales_product id, Requisition_id and date time [E]
	
	// delivery return update stock one by one from a list based on sales_main id and date_time [S]
	public void getProdcutIdForStockUpdate(String purchase_id, String date_time) {
		PurchaseProduct pp = new PurchaseProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_product_id, purchase_id, product_id, bonus_id, order_status, order_quantity FROM purchase_product WHERE purchase_id=? and date_time=?");
			
			ps.setString(1, purchase_id);
			ps.setString(2, date_time);
			
			rs = ps.executeQuery();
			
			while(rs.next()){
				
				String strPurchaseProduct = rs.getString("purchase_product_id");
				String strPurchaseMain = rs.getString("purchase_id");
				String strProduct = rs.getString("product_id");
				String strOrderStatus = rs.getString("order_status");
				int intOrderQuantity = rs.getInt("order_quantity");
				
				//if (strOrderStatus.equals("R") && strOrderStatus.equals("C")) {
					//pdao.returnStockUpdate(strProduct, intOrderQuantity);
					pdao.purchaseStockUpdate(strProduct, intOrderQuantity);
				//}
				
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
	}
	// delivery return update stock one by one from a list based on sales_main id and date_time [E]
	
	// based on requisition id and date time get one by one product and its quantity and tp_price [S]
	/*public void getProdcutIdForProfitLoss(String sales_id, String requisition_id, String date_time, String strFromAccount, double doubleTotalSalesAmount, String strCurrentDateTime) {
		PurchaseProduct pp = new PurchaseProduct();
		pldao = new ProfitLossDAO();
		double productTotalTpPrice = 0.00;
		
		try{
			ps = con.prepareStatement("SELECT purchase_product_id, purchase_id, product_id, bonus_id, order_status, order_quantity FROM purchase_product WHERE requisition_id=? and date_time=?");
			
			ps.setString(1, requisition_id);
			ps.setString(2, date_time);
			
			rs = ps.executeQuery();
			
			while(rs.next()){
				
				String strPurchaseProduct = rs.getString("purchase_product_id");
				String strPurchaseMain = rs.getString("purchase_id");
				String strRequisitionProduct = rs.getString("requisition_product_id");
				String strRequisition = rs.getString("requisition_id");
				String strProduct = rs.getString("product_id");
				String strOrderStatus = rs.getString("order_status");
				int intOrderQuantity = rs.getInt("order_quantity");
				
				double productTpPrice = 0.00;
				
				try{
					PreparedStatement ps1 = con.prepareStatement("SELECT product_id, tp_price FROM product where product_id=?");
					
					ps1.setString(1, strProduct);
					
					ResultSet rs1 = ps1.executeQuery();
					
					while(rs1.next()){
						
						String strProductId = rs.getString("product_id");
						double tpPrice = pdao.getProductById(strProductId).getTp_price();
						
						//totalTpPrice = tpPrice * intOrderQuantity;
						productTpPrice = Double.valueOf(df.format(tpPrice * intOrderQuantity));
						
					}
					
				} catch(Exception e){
					e.printStackTrace();
				}
				
				productTotalTpPrice += productTpPrice;
				
			}

			pldao.profitLossAmountAllProduct(sales_id, strFromAccount, doubleTotalSalesAmount, productTotalTpPrice, strCurrentDateTime);
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
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
	}*/
	// based on requisition id and date time get one by one product and its quantity and tp_price [E]
	
	// after approve insert into sales_product one by one from a list based on requisition_product id and date time [E]
	/*public void requisitionProductToSalesProduct(String strRequisitionProductId, String strRequisitionId, String strDateTime, String strProductId,
												String strProductName, String strPackType,String strPackSize, int intPieces, String strBonusId,
												String strBonusName, String strOrderPack, int intOrderQuantity, double doubleMrp, double doubleTotalMrp,
												double doubleDiscount, double doubleTotalAmount, String strOrderStatus, String strDeliveryStatus,
												String strCreated, String strUpdated){
		try{
			ps = con.prepareStatement("INSERT INTO purchase_product(purchase_product_id, purchase_id, purchase_type, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, rate_per_piceces, rate_per_box, order_pack, order_quantity, tp_price, total_tp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			SalesMainDAO smdao = new SalesMainDAO();
			
			SalesProductDAO spdao = new SalesProductDAO();
			
			ps.setString(1, spdao.getSalesProductID().getSales_product_id());
			ps.setString(2, smdao.getSalesMainByIdDateTime(strRequisitionId, strDateTime).getSales_id());
			ps.setString(3, "Requisition");
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
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}*/
	// after approve insert into sales_product one by one from a list based on requisition_product id and date time [E]
	
	// after delivery  approve insert into customer_purchase_product one by one from a list based on sales_product id and date time [S]
	/*public PurchaseProduct getPurchaseProductToCustomerPurchaseProduct(String requisition_id, String date_time){
		PurchaseProduct sp = new PurchaseProduct();
		
		try{
			ps = con.prepareStatement("SELECT purchase_product_id, purchase_id, purchase_type, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, rate_per_piceces, rate_per_box, order_pack, order_quantity, tp_price, total_tp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM purchase_product where requisition_id=? and date_time=?");
			
			ps.setString(1, requisition_id);
			ps.setString(2, date_time);
			
			rs = ps.executeQuery();
			
			while (rs.next()){
				
				String strPurchaseProductId = rs.getString("purchase_product_id");
				String strPurchaseId = rs.getString("purchase_id");
				String strType = rs.getString("purchase_type");
				String strDateTime = rs.getString("date_time");
				String strProductId = rs.getString("product_id");
				String strProductName = rs.getString("product_name");
				String strPackType = rs.getString("pack_type");
				String strPackSize = rs.getString("pack_size");
				int intPieces = rs.getInt("piceces");
				String strBonusId = rs.getString("bonus_id");
				String strBonusName = rs.getString("bonus_name");
				String strOrderPack = rs.getString("order_pack");
				int intOrderQuantity = rs.getInt("order_quantity");
				double doubleMrp = rs.getDouble("mrp_price");
				double doubleTotalMrp = rs.getDouble("total_mrp_price");
				double doubleDiscount = rs.getDouble("discount_amt");
				double doubleTotalAmount = rs.getDouble("total_amount");
				String strOrderStatus = rs.getString("order_status");
				String strDeliveryStatus = rs.getString("delivery_status");
				String strCreated = rs.getString("created");
				String strUpdated = rs.getString("updated");
				
				//spdao.requisitionProductToSalesProduct(requisition_id, date_time);
				cppdao.SalesProductToCustomerPurchaseProduct(strType, strRequisitionProductId, strRequisitionId, strDateTime, strProductId, strProductName, strPackType,
														strPackSize, intPieces, strBonusId,strBonusName, strOrderPack, intOrderQuantity, doubleMrp, 
														doubleTotalMrp, doubleDiscount, doubleTotalAmount, strOrderStatus, strDeliveryStatus,
														strCreated, strUpdated);
				
			}
		} catch (Exception e){
			e.printStackTrace();
		} finally {
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

		return sp;
	}*/
	// after delivery  approve insert into customer_purchase_product one by one from a list based on sales_product id and date time [E]
	
	// after delivery  return insert into transaction_product one by one from a list based on purchase_product id and date time [S]
	public PurchaseProduct getPurchaseProductToTransactionProduct(String purchase_id, String date_time){
		PurchaseProduct sp = new PurchaseProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_product_id, purchase_id, purchase_type, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, rate_per_piceces, rate_per_box, order_pack, order_quantity, tp_price, total_tp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM purchase_product where purchase_id=? and date_time=?");
			
			ps.setString(1, purchase_id);
			ps.setString(2, date_time);
			
			rs = ps.executeQuery();
			
			while (rs.next()){
				
				String strPurchaseProductId = rs.getString("purchase_product_id");
				String strPurchaseId = rs.getString("purchase_id");
				String strType = rs.getString("purchase_type");
				String strDateTime = rs.getString("date_time");
				String strProductId = rs.getString("product_id");
				String strProductName = rs.getString("product_name");
				String strPackType = rs.getString("pack_type");
				String strPackSize = rs.getString("pack_size");
				int intPieces = rs.getInt("piceces");
				String strBonusId = rs.getString("bonus_id");
				String strBonusName = rs.getString("bonus_name");
				double ratePerPieces = rs.getDouble("rate_per_piceces");
				double ratePerBox = rs.getDouble("rate_per_box");
				String strOrderPack = rs.getString("order_pack");
				int intOrderQuantity = rs.getInt("order_quantity");
				double tpPrice = rs.getDouble("tp_price");
				double doubleTotalTpPrice = rs.getDouble("total_tp_price");
				double doubleDiscount = rs.getDouble("discount_amt");
				double doubleTotalAmount = rs.getDouble("total_amount");
				String strOrderStatus = rs.getString("order_status");
				String strDeliveryStatus = rs.getString("delivery_status");
				String strCreated = rs.getString("created");
				String strUpdated = rs.getString("updated");
				String strCreatedBy = rs.getString("created_by");
				String strUpdatedBy = rs.getString("updated_by");
				
				tpdao = new TransactionProductDAO();
				tpdao.purchaseProductToTransactionProduct(strPurchaseProductId, strPurchaseId, strType, strDateTime, strProductId, strProductName, strPackType,
														strPackSize, intPieces, strBonusId,strBonusName, ratePerPieces, ratePerBox, strOrderPack, 
														intOrderQuantity, tpPrice, doubleTotalTpPrice, doubleDiscount, doubleTotalAmount, strOrderStatus,
														strDeliveryStatus, strCreated, strUpdated, strCreatedBy, strUpdatedBy);
				
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

		return sp;
	}
	// after delivery  return insert into transaction_product one by one from a list based on purchase_product id and date time [E]
	
	// after delivery  return insert into customer_transaction_product based on sales_product id, Requisition_id and date time [S]
	public PurchaseProduct purchaseProductToTransactionProduct(String purchase_product_id, String purchase_id, String date_time){
		PurchaseProduct pp = new PurchaseProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_product_id, purchase_id, purchase_type, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, rate_per_piceces, rate_per_box, order_pack, order_quantity, tp_price, total_tp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM purchase_product where purchase_product_id=? and purchase_id=? and date_time=?");
			
			ps.setString(1, purchase_product_id);
			ps.setString(2, purchase_id);
			ps.setString(3, date_time);
			
			rs = ps.executeQuery();
			
			while (rs.next()){
				
				String strPurchaseProductId = rs.getString("purchase_product_id");
				String strPurchaseId = rs.getString("purchase_id");
				String strType = rs.getString("purchase_type");
				String strDateTime = rs.getString("date_time");
				String strProductId = rs.getString("product_id");
				String strProductName = rs.getString("product_name");
				String strPackType = rs.getString("pack_type");
				String strPackSize = rs.getString("pack_size");
				int intPieces = rs.getInt("piceces");
				String strBonusId = rs.getString("bonus_id");
				String strBonusName = rs.getString("bonus_name");
				double ratePerPieces = rs.getDouble("rate_per_piceces");
				double ratePerBox = rs.getDouble("rate_per_box");
				String strOrderPack = rs.getString("order_pack");
				int intOrderQuantity = rs.getInt("order_quantity");
				double tpPrice = rs.getDouble("tp_price");
				double doubleTotalTpPrice = rs.getDouble("total_tp_price");
				double doubleDiscount = rs.getDouble("discount_amt");
				double doubleTotalAmount = rs.getDouble("total_amount");
				String strOrderStatus = rs.getString("order_status");
				String strDeliveryStatus = rs.getString("delivery_status");
				String strCreated = rs.getString("created");
				String strUpdated = rs.getString("updated");
				String strCreatedBy = rs.getString("created_by");
				String strUpdatedBy = rs.getString("updated_by");
				
				tpdao = new TransactionProductDAO();
				tpdao.purchaseProductToTransactionProduct(strPurchaseProductId, strPurchaseId, strType, strDateTime, strProductId, strProductName, strPackType,
														strPackSize, intPieces, strBonusId,strBonusName, ratePerPieces, ratePerBox, strOrderPack, 
														intOrderQuantity, tpPrice, doubleTotalTpPrice, doubleDiscount, doubleTotalAmount, strOrderStatus,
														strDeliveryStatus, strCreated, strUpdated, strCreatedBy, strUpdatedBy);
				
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

		return pp;
	}
	// after delivery  return insert into customer_transaction_product based on sales_product id, Requisition_id and date time [E]
	
}
