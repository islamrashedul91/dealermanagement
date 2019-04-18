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
import com.rashed.pharmacy.util.*;

public class SalesProductDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	private ProductDAO pdao;
	private RequisitionProductDAO rpdao;
	private CustomerPurchaseProductDAO cppdao;
	private CustomerTransactionProductDAO ctpdao;
	private ProfitLossDAO pldao;
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public SalesProductDAO(){
		//con  = DbUtil.getConnection();
		pdao = new ProductDAO();
		cppdao = new CustomerPurchaseProductDAO();
	}
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	// for decimal format [S]
	DecimalFormat df = new DecimalFormat("#.##");
	// for decimal format [S]
	
	public void save(SalesProduct sp){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO sales_product(sales_product_id, sales_id, sales_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO sales_product(sales_product_id, sales_id, sales_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, sp.getSales_product_id());
			ps.setString(2, sp.getSales_id());
			ps.setString(3, sp.getSales_type());
			ps.setString(4, sp.getRequisition_product_id());
			ps.setString(5, sp.getRequisition_id());
			ps.setString(6, sp.getDate_time());
			ps.setString(7, sp.getProduct_id());
			ps.setString(8, sp.getProduct_name());
			ps.setString(9, sp.getPack_type());
			ps.setString(10, sp.getPack_size());
			ps.setInt(11, sp.getPiceces());
			ps.setString(12, sp.getBonus_id());
			ps.setString(13, sp.getBonus_name());
			ps.setString(14, sp.getOrder_pack());
			ps.setInt(15, sp.getOrder_quantity());
			ps.setDouble(16, sp.getMrp_price());
			ps.setDouble(17, sp.getTotal_mrp_price());
			ps.setDouble(18, sp.getDiscount_amt());
			ps.setDouble(19, sp.getTotal_amount());
			ps.setString(20, sp.getOrder_status());
			ps.setString(21, sp.getDelivery_status());
			ps.setString(22, sp.getCreated());
			ps.setString(23, sp.getUpdated());
			ps.setString(24, sp.getCreated_by());
			ps.setString(25, sp.getUpdated_by());
			
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
	
	public void delete(String sales_product_id){
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM sales_product WHERE sales_product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM sales_product WHERE sales_product_id=?");
			
			ps.setString(1, sales_product_id);
			
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
	
	public void deleteByIdDateTime(String requisition_id, String date_time){

		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM sales_product WHERE requisition_id=? and date_time=?");
			
			ps.setString(1, requisition_id);
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
	public void deleteBySPIdRIdDateTime(String sales_product_id, String requisition_id, String date_time){

		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM sales_product WHERE sales_product_id=? and requisition_id=? and date_time=?");
			
			ps.setString(1, sales_product_id);
			ps.setString(2, requisition_id);
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
	
	public void update(SalesProduct sp){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales_product set sales_id=?, sales_type=?, requisition_product_id=?, requisition_id=?, date_time=?, product_id=?, product_name=?, pack_type=?, pack_size=?, piceces=?, bonus_id=?, bonus_name=?, order_pack=?, order_quantity=?, mrp_price=?, total_mrp_price=?, discount_amt=?, total_amount=?, order_status=?, delivery_status=?, created=?, updated=?, created_by=?, updated_by=? where requisition_product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales_product set sales_id=?, sales_type=?, requisition_product_id=?, requisition_id=?, date_time=?, product_id=?, product_name=?, pack_type=?, pack_size=?, piceces=?, bonus_id=?, bonus_name=?, order_pack=?, order_quantity=?, mrp_price=?, total_mrp_price=?, discount_amt=?, total_amount=?, order_status=?, delivery_status=?, created=?, updated=?, created_by=?, updated_by=? where sales_product_id=?");
			
			ps.setString(1, sp.getSales_id());
			ps.setString(2, sp.getSales_type());
			ps.setString(3, sp.getRequisition_product_id());
			ps.setString(4, sp.getRequisition_id());
			ps.setString(5, sp.getDate_time());
			ps.setString(6, sp.getProduct_id());
			ps.setString(7, sp.getProduct_name());
			ps.setString(8, sp.getPack_type());
			ps.setString(9, sp.getPack_size());
			ps.setInt(10, sp.getPiceces());
			ps.setString(11, sp.getBonus_id());
			ps.setString(12, sp.getBonus_name());
			ps.setString(13, sp.getOrder_pack());
			ps.setInt(14, sp.getOrder_quantity());
			ps.setDouble(15, sp.getMrp_price());
			ps.setDouble(16, sp.getTotal_mrp_price());
			ps.setDouble(17, sp.getDiscount_amt());
			ps.setDouble(18, sp.getTotal_amount());
			ps.setString(19, sp.getOrder_status());
			ps.setString(20, sp.getDelivery_status());
			ps.setString(21, sp.getCreated());
			ps.setString(22, sp.getUpdated());
			ps.setString(23, sp.getCreated_by());
			ps.setString(24, sp.getUpdated_by());
			ps.setString(25, sp.getSales_product_id());
			
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
	
	public void cancel(String sales_product_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales_product set order_status=?, updated=? where sales_product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales_product set order_status=?, updated=? where sales_product_id=?");
			
			ps.setString(1, "C");
			ps.setString(2, strDate);
			ps.setString(3, sales_product_id);
			
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
	
	public void approve(String sales_product_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales_product set order_status=?, updated=? where sales_product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales_product set order_status=?, updated=? where sales_product_id=?");
			
			ps.setString(1, "S");
			ps.setString(2, strDate);
			ps.setString(3, sales_product_id);
			
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
	public void approveByMainSales(String requisition_id, String date_time){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales_product set order_status=?, updated=? where requisition_id=? and date_time=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales_product set order_status=?, updated=? where requisition_id=? and date_time=?");
			
			ps.setString(1, "S");
			ps.setString(2, strDate);
			ps.setString(3, requisition_id);
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
	
	public void deliveryApproveByMainSales(String sales_id, String requisition_id, String date_time){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales_product set delivery_status=?, updated=? where requisition_id=? and date_time=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales_product set delivery_status=?, updated=? where sales_id=? and requisition_id=? and date_time=?");
			
			ps.setString(1, "D");
			ps.setString(2, strDate);
			ps.setString(3, sales_id);
			ps.setString(4, requisition_id);
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
	
	public void deliveryReturn(String sales_product_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales_product set delivery_status=?, updated=? where sales_product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales_product set delivery_status=?, updated=? where sales_product_id=?");
			
			ps.setString(1, "R");
			ps.setString(2, strDate);
			ps.setString(3, sales_product_id);
			
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
	
	public void deliveryReturnByMainSales(String sales_id, String requisition_id, String date_time){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales_product set delivery_status=?, updated=? where requisition_id=? and date_time=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales_product set delivery_status=?, updated=? where sales_id=? and requisition_id=? and date_time=?");
			
			ps.setString(1, "R");
			ps.setString(2, strDate);
			ps.setString(3, sales_id);
			ps.setString(4, requisition_id);
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
	
	// delivery return from sales product screen [S]
	public void deliveryReturnBySalesProduct(String sales_product_id, String requisition_id, String date_time){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales_product set delivery_status=?, updated=? where sales_product_id=? and requisition_id=? and date_time=?");
			
			ps.setString(1, "R");
			ps.setString(2, strDate);
			ps.setString(3, sales_product_id);
			ps.setString(4, requisition_id);
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
	
	public List<SalesProduct> getAllSalesProduct(){
		List<SalesProduct> list = new ArrayList<SalesProduct>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT sales_product_id, sales_id, sales_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM sales_product ORDER BY created DESC");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_product_id, sales_id, sales_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM sales_product ORDER BY created DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				SalesProduct sp = new SalesProduct();				
				
				sp.setSales_product_id(rs.getString(1));
				sp.setSales_id(rs.getString(2));
				sp.setSales_type(rs.getString(3));
				sp.setRequisition_product_id(rs.getString(4));
				sp.setRequisition_id(rs.getString(5));
				sp.setDate_time(rs.getString(6));
				sp.setProduct_id(rs.getString(7));
				sp.setProduct_name(rs.getString(8));
				sp.setPack_type(rs.getString(9));
				sp.setPack_size(rs.getString(10));
				sp.setPiceces(rs.getInt(11));
				sp.setBonus_id(rs.getString(12));
				sp.setBonus_name(rs.getString(13));
				sp.setOrder_pack(rs.getString(14));
				sp.setOrder_quantity(rs.getInt(15));
				sp.setMrp_price(rs.getDouble(16));
				sp.setTotal_mrp_price(rs.getDouble(17));
				sp.setDiscount_amt(rs.getDouble(18));
				sp.setTotal_amount(rs.getDouble(19));
				sp.setOrder_status(rs.getString(20));
				sp.setDelivery_status(rs.getString(21));
				sp.setCreated(rs.getString(22));
				sp.setUpdated(rs.getString(23));
				sp.setCreated_by(rs.getString(24));
				sp.setUpdated_by(rs.getString(25));
			
				list.add(sp);				
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
	
	public SalesProduct getSalesProductById(String sales_product_id){
		SalesProduct sp = new SalesProduct();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT sales_product_id, sales_id, sales_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM sales_product where sales_product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_product_id, sales_id, sales_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM sales_product where sales_product_id=?");
			
			ps.setString(1, sales_product_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				sp.setSales_product_id(rs.getString(1));
				sp.setSales_id(rs.getString(2));
				sp.setSales_type(rs.getString(3));
				sp.setRequisition_product_id(rs.getString(4));
				sp.setRequisition_id(rs.getString(5));
				sp.setDate_time(rs.getString(6));
				sp.setProduct_id(rs.getString(7));
				sp.setProduct_name(rs.getString(8));
				sp.setPack_type(rs.getString(9));
				sp.setPack_size(rs.getString(10));
				sp.setPiceces(rs.getInt(11));
				sp.setBonus_id(rs.getString(12));
				sp.setBonus_name(rs.getString(13));
				sp.setOrder_pack(rs.getString(14));
				sp.setOrder_quantity(rs.getInt(15));
				sp.setMrp_price(rs.getDouble(16));
				sp.setTotal_mrp_price(rs.getDouble(17));
				sp.setDiscount_amt(rs.getDouble(18));
				sp.setTotal_amount(rs.getDouble(19));
				sp.setOrder_status(rs.getString(20));
				sp.setDelivery_status(rs.getString(21));
				sp.setCreated(rs.getString(22));
				sp.setUpdated(rs.getString(23));
				sp.setCreated_by(rs.getString(24));
				sp.setUpdated_by(rs.getString(25));
				
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
	
	// generated auto increment id during add [S]
	public SalesProduct getSalesProductID(){
		SalesProduct sp = new SalesProduct();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT sales_product_id FROM sales_product");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_product_id FROM sales_product");
			
			rs = ps.executeQuery();
			
			int sales_product_id = 0;
			
			if(rs.next() == false) {
				sales_product_id = 1000000000;
				sales_product_id = sales_product_id+1;
				sp.setSales_product_id("SPDT" + String.valueOf(sales_product_id));
			} else {
				if(rs.last()) {
					String strSalesProduct = rs.getString("sales_product_id");
					sales_product_id = Integer.parseInt(strSalesProduct.replaceAll("[^0-9]", ""));
					sales_product_id = sales_product_id+1;
					sp.setSales_product_id("SPDT" + String.valueOf(sales_product_id));
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
		
		return sp;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public SalesProduct getSelectedOtherID(String sales_product_id){
		SalesProduct sp = new SalesProduct();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT sales_product_id, sales_id, requisition_product_id, requisition_id, product_id, bonus_id, order_status, order_quantity FROM sales_product WHERE sales_product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_product_id, sales_id, sales_type, requisition_product_id, requisition_id, date_time, product_id, bonus_id, order_status, delivery_status, order_quantity FROM sales_product WHERE sales_product_id=?");
			
			ps.setString(1, sales_product_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strSalesProduct = rs.getString("sales_product_id");
				String strSalesMain = rs.getString("sales_id");
				String strSalesType = rs.getString("sales_type");
				String strRequisitionProduct = rs.getString("requisition_product_id");
				String strRequisition = rs.getString("requisition_id");
				String strDateTime = rs.getString("date_time");
				String strProduct = rs.getString("product_id");
				String strBonus = rs.getString("bonus_id");
				String strOrderStatus = rs.getString("order_status");
				String strDeliveryStatus = rs.getString("delivery_status");
				int intOrderQuantity = rs.getInt("order_quantity");
				
				sp.setSales_product_id(strSalesProduct);
				sp.setSales_id(strSalesMain);
				sp.setSales_type(strSalesType);
				sp.setRequisition_product_id(strRequisitionProduct);
				sp.setRequisition_id(strRequisition);
				sp.setDate_time(strDateTime);
				sp.setProduct_id(strProduct);
				sp.setBonus_id(strBonus);
				sp.setOrder_status(strOrderStatus);
				sp.setDelivery_status(strDeliveryStatus);
				sp.setOrder_quantity(intOrderQuantity);
				
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
	// selected other respective id during update [E]
	
	/*public RequisitionProduct getRequisitionMultiById(String requisition_id){
		RequisitionProduct rp = new RequisitionProduct();*/
	public List<SalesProduct> getAllSalesProductByMainIdDateTime(String sales_id, String requisition_id, String strDateTime){
		List<SalesProduct> list = new ArrayList<SalesProduct>();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT sales_product_id, sales_id, sales_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM sales_product where requisition_id=? and date_time=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_product_id, sales_id, sales_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM sales_product where sales_id=? and requisition_id=? and date_time=?");
			
			ps.setString(1, sales_id);
			ps.setString(2, requisition_id);
			ps.setString(3, strDateTime);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			while (rs.next()) {
				SalesProduct sp = new SalesProduct();				
				
				sp.setSales_product_id(rs.getString(1));
				sp.setSales_id(rs.getString(2));
				sp.setSales_type(rs.getString(3));
				sp.setRequisition_product_id(rs.getString(4));
				sp.setRequisition_id(rs.getString(5));
				sp.setDate_time(rs.getString(6));
				sp.setProduct_id(rs.getString(7));
				sp.setProduct_name(rs.getString(8));
				sp.setPack_type(rs.getString(9));
				sp.setPack_size(rs.getString(10));
				sp.setPiceces(rs.getInt(11));
				sp.setBonus_id(rs.getString(12));
				sp.setBonus_name(rs.getString(13));
				sp.setOrder_pack(rs.getString(14));
				sp.setOrder_quantity(rs.getInt(15));
				sp.setMrp_price(rs.getDouble(16));
				sp.setTotal_mrp_price(rs.getDouble(17));
				sp.setDiscount_amt(rs.getDouble(18));
				sp.setTotal_amount(rs.getDouble(19));
				sp.setOrder_status(rs.getString(20));
				sp.setDelivery_status(rs.getString(21));
				sp.setCreated(rs.getString(22));
				sp.setUpdated(rs.getString(23));
				sp.setCreated_by(rs.getString(24));
				sp.setUpdated_by(rs.getString(25));
			
				list.add(sp);				
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
	public SalesProduct sumTotalAmount(String sales_id, String requisition_id, String date_time){
		SalesProduct sp = new SalesProduct();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT sum(total_amount) FROM sales_product where requisition_id=? and date_time=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sum(total_amount) FROM sales_product where sales_id=? and requisition_id=? and date_time=?");
			
			ps.setString(1, sales_id);
			ps.setString(2, requisition_id);
			ps.setString(3, date_time);
			
			//ResultSet rs = ps.executeQuery();
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
	public SalesProduct sumTotalAmountBasedOnReturnStatus(String requisition_id, String date_time){
		SalesProduct sp = new SalesProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sum(total_amount) FROM sales_product where requisition_id=? and date_time=? and delivery_status=?");
			
			ps.setString(1, requisition_id);
			ps.setString(2, date_time);
			ps.setString(3, "R");
			
			//ResultSet rs = ps.executeQuery();
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
	// after delivery  return insert into customer_transaction_main based on sales_product id, Requisition_id and date time [E]
	
	// delivery return update stock one by one from a list based on sales_main id and date_time [S]
	public void getProdcutIdForStockUpdate(String requisition_id, String date_time) {
		SalesProduct rp = new SalesProduct();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT sales_product_id, sales_id, requisition_product_id, requisition_id, product_id, bonus_id, order_status, order_quantity FROM sales_product WHERE requisition_id=? and date_time=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_product_id, sales_id, requisition_product_id, requisition_id, product_id, bonus_id, order_status, order_quantity FROM sales_product WHERE requisition_id=? and date_time=?");
			
			ps.setString(1, requisition_id);
			ps.setString(2, date_time);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			while(rs.next()){
				
				String strSalesProduct = rs.getString("sales_product_id");
				String strSalesMain = rs.getString("sales_id");
				String strRequisitionProduct = rs.getString("requisition_product_id");
				String strRequisition = rs.getString("requisition_id");
				String strProduct = rs.getString("product_id");
				String strOrderStatus = rs.getString("order_status");
				int intOrderQuantity = rs.getInt("order_quantity");
				
				//if (strOrderStatus.equals("R") && strOrderStatus.equals("C")) {
					pdao.returnStockUpdate(strProduct, intOrderQuantity);
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
	public void getProdcutIdForProfitLoss(String sales_id, String requisition_id, String date_time, String strFromAccount, double doubleTotalSalesAmount, String strCurrentDateTime) {
		SalesProduct rp = new SalesProduct();
		pldao = new ProfitLossDAO();
		double productTotalTpPrice = 0.00;
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_product_id, sales_id, requisition_product_id, requisition_id, product_id, bonus_id, order_status, order_quantity FROM sales_product WHERE requisition_id=? and date_time=?");
			
			ps.setString(1, requisition_id);
			ps.setString(2, date_time);
			
			rs = ps.executeQuery();
			
			while(rs.next()){
				
				String strSalesProduct = rs.getString("sales_product_id");
				String strSalesMain = rs.getString("sales_id");
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
	// based on requisition id and date time get one by one product and its quantity and tp_price [E]
	
	// after approve insert into sales_product one by one from a list based on requisition_product id and date time [E]
	public void requisitionProductToSalesProduct(String strRequisitionProductId, String strRequisitionId, String strDateTime, String strProductId,
												String strProductName, String strPackType,String strPackSize, int intPieces, String strBonusId,
												String strBonusName, String strOrderPack, int intOrderQuantity, double doubleMrp, double doubleTotalMrp,
												double doubleDiscount, double doubleTotalAmount, String strOrderStatus, String strDeliveryStatus,
												String strCreated, String strUpdated){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO sales_product(sales_product_id, sales_id, sales_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO sales_product(sales_product_id, sales_id, sales_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
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
	// after approve insert into sales_product one by one from a list based on requisition_product id and date time [E]
	
	// after delivery  approve insert into customer_purchase_product one by one from a list based on sales_product id and date time [S]
	public SalesProduct getSalesProductToCustomerPurchaseProduct(String requisition_id, String date_time){
		SalesProduct sp = new SalesProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_product_id, sales_id, sales_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM sales_product where requisition_id=? and date_time=?");
			
			ps.setString(1, requisition_id);
			ps.setString(2, date_time);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			while (rs.next()){
				
				String strSalesProductId = rs.getString("sales_product_id");
				String strSalesId = rs.getString("sales_id");
				String strType = rs.getString("sales_type");
				String strRequisitionProductId = rs.getString("requisition_product_id");
				String strRequisitionId = rs.getString("requisition_id");
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
	// after delivery  approve insert into customer_purchase_product one by one from a list based on sales_product id and date time [E]
	
	// after delivery  return insert into customer_transaction_product one by one from a list based on sales_product id and date time [S]
	public SalesProduct getSalesProductToCustomerTransactionProduct(String requisition_id, String date_time){
		SalesProduct sp = new SalesProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_product_id, sales_id, sales_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM sales_product where requisition_id=? and date_time=?");
			
			ps.setString(1, requisition_id);
			ps.setString(2, date_time);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			while (rs.next()){
				
				String strSalesProductId = rs.getString("sales_product_id");
				String strSalesId = rs.getString("sales_id");
				String strType = rs.getString("sales_type");
				String strRequisitionProductId = rs.getString("requisition_product_id");
				String strRequisitionId = rs.getString("requisition_id");
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
				
				ctpdao = new CustomerTransactionProductDAO();
				ctpdao.SalesProductToCustomerTransactionProduct(strType, strRequisitionProductId, strRequisitionId, strDateTime, strProductId, strProductName, strPackType,
														strPackSize, intPieces, strBonusId,strBonusName, strOrderPack, intOrderQuantity, doubleMrp, 
														doubleTotalMrp, doubleDiscount, doubleTotalAmount, strOrderStatus, strDeliveryStatus,
														strCreated, strUpdated);
				
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
	// after delivery  return insert into customer_transaction_product one by one from a list based on sales_product id and date time [E]
	
	// after delivery  return insert into customer_transaction_product based on sales_product id, Requisition_id and date time [S]
	public SalesProduct salesProductToCustomerTransactionProduct(String sales_product_id, String requisition_id, String date_time){
		SalesProduct sp = new SalesProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_product_id, sales_id, sales_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM sales_product where sales_product_id=? and requisition_id=? and date_time=?");
			
			ps.setString(1, sales_product_id);
			ps.setString(2, requisition_id);
			ps.setString(3, date_time);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			while (rs.next()){
				
				String strSalesProductId = rs.getString("sales_product_id");
				String strSalesId = rs.getString("sales_id");
				String strType = rs.getString("sales_type");
				String strRequisitionProductId = rs.getString("requisition_product_id");
				String strRequisitionId = rs.getString("requisition_id");
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
				
				ctpdao = new CustomerTransactionProductDAO();
				ctpdao.SalesProductToCustomerTransactionProduct(strType, strRequisitionProductId, strRequisitionId, strDateTime, strProductId, strProductName, strPackType,
														strPackSize, intPieces, strBonusId,strBonusName, strOrderPack, intOrderQuantity, doubleMrp, 
														doubleTotalMrp, doubleDiscount, doubleTotalAmount, strOrderStatus, strDeliveryStatus,
														strCreated, strUpdated);
				
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
	// after delivery  return insert into customer_transaction_product based on sales_product id, Requisition_id and date time [E]
	
}
