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
import com.rashed.pharmacy.util.*;

public class RequisitionProductDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	private ProductDAO pdao;
	private SalesProductDAO spdao;
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public RequisitionProductDAO(){
		//con  = DbUtil.getConnection();
		pdao = new ProductDAO();
		spdao = new SalesProductDAO();
	}
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public void save(RequisitionProduct rp){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO requisition_product(requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO requisition_product(requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, rp.getRequisition_product_id());
			ps.setString(2, rp.getRequisition_id());
			ps.setString(3, rp.getDate_time());
			ps.setString(4, rp.getProduct_id());
			ps.setString(5, rp.getProduct_name());
			ps.setString(6, rp.getPack_type());
			ps.setString(7, rp.getPack_size());
			ps.setInt(8, rp.getPiceces());
			ps.setString(9, rp.getBonus_id());
			ps.setString(10, rp.getBonus_name());
			ps.setString(11, rp.getOrder_pack());
			ps.setInt(12, rp.getOrder_quantity());
			ps.setDouble(13, rp.getMrp_price());
			ps.setDouble(14, rp.getTotal_mrp_price());
			ps.setDouble(15, rp.getDiscount_amt());
			ps.setDouble(16, rp.getTotal_amount());
			ps.setString(17, rp.getOrder_status());
			ps.setString(18, rp.getDelivery_status());
			ps.setString(19, rp.getCreated());
			ps.setString(20, rp.getUpdated());
			
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
	
	public void delete(String requisition_product_id){
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM requisition_product WHERE requisition_product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM requisition_product WHERE requisition_product_id=?");
			
			ps.setString(1, requisition_product_id);
			
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
			ps = con.prepareStatement("DELETE FROM requisition_product WHERE requisition_id=? and date_time=?");
			
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
	
	public void update(RequisitionProduct rp){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE requisition_product set requisition_id=?, date_time=?, product_id=?, product_name=?, pack_type=?, pack_size=?, piceces=?, bonus_id=?, bonus_name=?, order_pack=?, order_quantity=?, mrp_price=?, total_mrp_price=?, discount_amt=?, total_amount=?, order_status=?, delivery_status=?, created=?, updated=? where requisition_product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE requisition_product set requisition_id=?, date_time=?, product_id=?, product_name=?, pack_type=?, pack_size=?, piceces=?, bonus_id=?, bonus_name=?, order_pack=?, order_quantity=?, mrp_price=?, total_mrp_price=?, discount_amt=?, total_amount=?, order_status=?, delivery_status=?, created=?, updated=? where requisition_product_id=?");
			
			ps.setString(1, rp.getRequisition_id());
			ps.setString(2, rp.getDate_time());
			ps.setString(3, rp.getProduct_id());
			ps.setString(4, rp.getProduct_name());
			ps.setString(5, rp.getPack_type());
			ps.setString(6, rp.getPack_size());
			ps.setInt(7, rp.getPiceces());
			ps.setString(8, rp.getBonus_id());
			ps.setString(9, rp.getBonus_name());
			ps.setString(10, rp.getOrder_pack());
			ps.setInt(11, rp.getOrder_quantity());
			ps.setDouble(12, rp.getMrp_price());
			ps.setDouble(13, rp.getTotal_mrp_price());
			ps.setDouble(14, rp.getDiscount_amt());
			ps.setDouble(15, rp.getTotal_amount());
			ps.setString(16, rp.getOrder_status());
			ps.setString(17, rp.getDelivery_status());
			ps.setString(18, rp.getCreated());
			ps.setString(19, rp.getUpdated());
			ps.setString(20, rp.getRequisition_product_id());
			
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
	
	public void cancel(String requisition_product_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE requisition_product set order_status=?, updated=? where requisition_product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE requisition_product set order_status=?, updated=? where requisition_product_id=?");
			
			ps.setString(1, "C");
			ps.setString(2, strDate);
			ps.setString(3, requisition_product_id);
			
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
	
	public void approve(String requisition_product_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE requisition_product set order_status=?, updated=? where requisition_product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE requisition_product set order_status=?, updated=? where requisition_product_id=?");
			
			ps.setString(1, "A");
			ps.setString(2, strDate);
			ps.setString(3, requisition_product_id);
			
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
	public void approveByMultiRequisition(String requisition_id, String date_time){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE requisition_product set order_status=?, updated=? where requisition_id=? and date_time=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE requisition_product set order_status=?, updated=? where requisition_id=? and date_time=?");
			
			ps.setString(1, "A");
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
	
	public List<RequisitionProduct> getAllRequisitionProduct(){
		List<RequisitionProduct> list = new ArrayList<RequisitionProduct>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated FROM requisition_product ORDER BY created DESC");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated FROM requisition_product ORDER BY created DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				RequisitionProduct rp = new RequisitionProduct();				
				
				rp.setRequisition_product_id(rs.getString(1));
				rp.setRequisition_id(rs.getString(2));
				rp.setDate_time(rs.getString(3));
				rp.setProduct_id(rs.getString(4));
				rp.setProduct_name(rs.getString(5));
				rp.setPack_type(rs.getString(6));
				rp.setPack_size(rs.getString(7));
				rp.setPiceces(rs.getInt(8));
				rp.setBonus_id(rs.getString(9));
				rp.setBonus_name(rs.getString(10));
				rp.setOrder_pack(rs.getString(11));
				rp.setOrder_quantity(rs.getInt(12));
				rp.setMrp_price(rs.getDouble(13));
				rp.setTotal_mrp_price(rs.getDouble(14));
				rp.setDiscount_amt(rs.getDouble(15));
				rp.setTotal_amount(rs.getDouble(16));
				rp.setOrder_status(rs.getString(17));
				rp.setDelivery_status(rs.getString(18));
				rp.setCreated(rs.getString(19));
				rp.setUpdated(rs.getString(20));
			
				list.add(rp);				
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
	
	public RequisitionProduct getRequisitionProductById(String requisition_product_id){
		RequisitionProduct rp = new RequisitionProduct();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated FROM requisition_product where requisition_product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated FROM requisition_product where requisition_product_id=?");
			
			ps.setString(1, requisition_product_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				rp.setRequisition_product_id(rs.getString(1));
				rp.setRequisition_id(rs.getString(2));
				rp.setDate_time(rs.getString(3));
				rp.setProduct_id(rs.getString(4));
				rp.setProduct_name(rs.getString(5));
				rp.setPack_type(rs.getString(6));
				rp.setPack_size(rs.getString(7));
				rp.setPiceces(rs.getInt(8));
				rp.setBonus_id(rs.getString(9));
				rp.setBonus_name(rs.getString(10));
				rp.setOrder_pack(rs.getString(11));
				rp.setOrder_quantity(rs.getInt(12));
				rp.setMrp_price(rs.getDouble(13));
				rp.setTotal_mrp_price(rs.getDouble(14));
				rp.setDiscount_amt(rs.getDouble(15));
				rp.setTotal_amount(rs.getDouble(16));
				rp.setOrder_status(rs.getString(17));
				rp.setDelivery_status(rs.getString(18));
				rp.setCreated(rs.getString(19));
				rp.setUpdated(rs.getString(20));
				
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

		return rp;
	}
	
	// generated auto increment id during add [S]
	public RequisitionProduct getRequisitionProductID(){
		RequisitionProduct rp = new RequisitionProduct();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT requisition_product_id FROM requisition_product");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT requisition_product_id FROM requisition_product");
			
			rs = ps.executeQuery();
			
			int requisition_product_id = 0;
			
			if(rs.next() == false) {
				requisition_product_id = 1000000000;
				requisition_product_id = requisition_product_id+1;
				rp.setRequisition_product_id("RPDT" + String.valueOf(requisition_product_id));
			} else {
				if(rs.last()) {
					String strRequisitionProduct = rs.getString("requisition_product_id");
					requisition_product_id = Integer.parseInt(strRequisitionProduct.replaceAll("[^0-9]", ""));
					requisition_product_id = requisition_product_id+1;
					rp.setRequisition_product_id("RPDT" + String.valueOf(requisition_product_id));
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
		
		return rp;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public RequisitionProduct getSelectedOtherID(String requisition_product_id){
		RequisitionProduct rp = new RequisitionProduct();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT requisition_product_id, requisition_id, product_id, bonus_id, order_status, order_quantity FROM requisition_product WHERE requisition_product_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT requisition_product_id, requisition_id, product_id, bonus_id, order_status, order_quantity FROM requisition_product WHERE requisition_product_id=?");
			
			ps.setString(1, requisition_product_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strRequisitionProduct = rs.getString("requisition_product_id");
				String strRequisition = rs.getString("requisition_id");
				String strProduct = rs.getString("product_id");
				String strBonus = rs.getString("bonus_id");
				String strOrderStatus = rs.getString("order_status");
				int intOrderQuantity = rs.getInt("order_quantity");
				
				rp.setRequisition_id(strRequisition);
				rp.setProduct_id(strProduct);
				rp.setBonus_id(strBonus);
				rp.setOrder_status(strOrderStatus);
				rp.setOrder_quantity(intOrderQuantity);
				
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
		
		return rp;
	}
	// selected other respective id during update [E]
	
	/*public RequisitionProduct getRequisitionMultiById(String requisition_id){
		RequisitionProduct rp = new RequisitionProduct();*/
	public List<RequisitionProduct> getAllRequisitionProductByMultiId(String requisition_id, String strDateTime){
		List<RequisitionProduct> list = new ArrayList<RequisitionProduct>();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated FROM requisition_product where requisition_id=? and date_time=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated FROM requisition_product where requisition_id=? and date_time=?");
			
			ps.setString(1, requisition_id);
			ps.setString(2, strDateTime);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			while (rs.next()) {
				RequisitionProduct rp = new RequisitionProduct();				
				
				rp.setRequisition_product_id(rs.getString(1));
				rp.setRequisition_id(rs.getString(2));
				rp.setDate_time(rs.getString(3));
				rp.setProduct_id(rs.getString(4));
				rp.setProduct_name(rs.getString(5));
				rp.setPack_type(rs.getString(6));
				rp.setPack_size(rs.getString(7));
				rp.setPiceces(rs.getInt(8));
				rp.setBonus_id(rs.getString(9));
				rp.setBonus_name(rs.getString(10));
				rp.setOrder_pack(rs.getString(11));
				rp.setOrder_quantity(rs.getInt(12));
				rp.setMrp_price(rs.getDouble(13));
				rp.setTotal_mrp_price(rs.getDouble(14));
				rp.setDiscount_amt(rs.getDouble(15));
				rp.setTotal_amount(rs.getDouble(16));
				rp.setOrder_status(rs.getString(17));
				rp.setDelivery_status(rs.getString(18));
				rp.setCreated(rs.getString(19));
				rp.setUpdated(rs.getString(20));
			
				list.add(rp);				
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
	public RequisitionProduct sumTotalAmount(String requisition_id, String date_time){
		RequisitionProduct rp = new RequisitionProduct();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT sum(total_amount) FROM requisition_product where requisition_id=? and date_time=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sum(total_amount) FROM requisition_product where requisition_id=? and date_time=?");
			
			ps.setString(1, requisition_id);
			ps.setString(2, date_time);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if (rs.next()) {
				rp.setTotal_amount(rs.getDouble(1));
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
		
		return rp;
	}
	// for Requisition Product sum total amount [E]
	
	// for update stock one by one from a list based on requisition_multi id and date_time [S]
	public void getProdcutIdForStockUpdate(String requisition_id, String date_time) {
		RequisitionProduct rp = new RequisitionProduct();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT requisition_product_id, requisition_id, product_id, bonus_id, order_status, order_quantity FROM requisition_product WHERE requisition_id=? and date_time=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT requisition_product_id, requisition_id, product_id, bonus_id, order_status, order_quantity FROM requisition_product WHERE requisition_id=? and date_time=?");
			
			ps.setString(1, requisition_id);
			ps.setString(2, date_time);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			while(rs.next()){
				
				String strRequisitionProduct = rs.getString("requisition_product_id");
				String strRequisition = rs.getString("requisition_id");
				String strProduct = rs.getString("product_id");
				String strOrderStatus = rs.getString("order_status");
				int intOrderQuantity = rs.getInt("order_quantity");
				
				if (strOrderStatus.equals("A") && !strOrderStatus.equals("C")) {
					pdao.stockUpdate(strProduct, intOrderQuantity);
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
	}
	// for update stock one by one from a list based on requisition_multi id and date_time [E]
	
	// after approve insert into sales_product one by one from a list based on requisition_product id and date time [S]
	public RequisitionProduct getRequisitionProductToSalesProduct(String requisition_id, String date_time){
		RequisitionProduct rp = new RequisitionProduct();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated FROM requisition_product where requisition_id=? and date_time=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated FROM requisition_product where requisition_id=? and date_time=?");
			
			ps.setString(1, requisition_id);
			ps.setString(2, date_time);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			while (rs.next()){
				
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
				spdao.requisitionProductToSalesProduct(strRequisitionProductId, strRequisitionId, strDateTime, strProductId, strProductName, strPackType,
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

		return rp;
	}
	// after approve insert into sales_product one by one from a list based on requisition_product id and date time [E]
	
}
