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

import com.rashed.pharmacy.model.ExpenseProduct;
import com.rashed.pharmacy.util.*;

public class ExpenseProductDAO {
	
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
	
	public ExpenseProductDAO(){
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
	
	public void save(ExpenseProduct ep){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO expense_product(expense_product_id, expense_id, expense_type, date_time, category_id, category_name, quantity, price, total_price, discount_amt, total_amount, order_status, expense_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, ep.getExpense_product_id());
			ps.setString(2, ep.getExpense_id());
			ps.setString(3, ep.getExpense_type());
			ps.setString(4, ep.getDate_time());
			ps.setString(5, ep.getCategory_id());
			ps.setString(6, ep.getCategory_name());
			ps.setInt(7, ep.getQuantity());
			ps.setDouble(8, ep.getPrice());
			ps.setDouble(9, ep.getTotal_price());
			ps.setDouble(10, ep.getDiscount_amt());
			ps.setDouble(11, ep.getTotal_amount());
			ps.setString(12, ep.getOrder_status());
			ps.setString(13, ep.getExpense_status());
			ps.setString(14, ep.getCreated());
			ps.setString(15, ep.getUpdated());
			ps.setString(16, ep.getCreated_by());
			ps.setString(17, ep.getUpdated_by());
			
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
	
	public void delete(String expense_product_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM expense_product WHERE expense_product_id=?");
			
			ps.setString(1, expense_product_id);
			
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
			ps = con.prepareStatement("DELETE FROM expense_product WHERE expense_id=? and date_time=?");
			
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
	
	// delivery return from sales product screen [S]
	public void deleteByEPIdEIdDateTime(String expense_product_id, String expense_id, String date_time){

		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM expense_product WHERE expense_product_id=? and expense_id=? and date_time=?");
			
			ps.setString(1, expense_product_id);
			ps.setString(2, expense_id);
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
	
	public void update(ExpenseProduct ep){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE expense_product set expense_id=?, expense_type=?, date_time=?, category_id=?, category_name=?, quantity=?, price=?, total_price=?, discount_amt=?, total_amount=?, order_status=?, expense_status=?, created=?, updated=?, created_by=?, updated_by=? where expense_product_id=?");
			
			ps.setString(1, ep.getExpense_id());
			ps.setString(2, ep.getExpense_type());
			ps.setString(3, ep.getDate_time());
			ps.setString(4, ep.getCategory_id());
			ps.setString(5, ep.getCategory_name());
			ps.setInt(6, ep.getQuantity());
			ps.setDouble(7, ep.getPrice());
			ps.setDouble(8, ep.getTotal_price());
			ps.setDouble(9, ep.getDiscount_amt());
			ps.setDouble(10, ep.getTotal_amount());
			ps.setString(11, ep.getOrder_status());
			ps.setString(12, ep.getExpense_status());
			ps.setString(13, ep.getCreated());
			ps.setString(14, ep.getUpdated());
			ps.setString(15, ep.getCreated_by());
			ps.setString(16, ep.getUpdated_by());
			ps.setString(17, ep.getExpense_product_id());
			
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
	
	public void cancel(String expense_product_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE expense_product set order_status=?, updated=? where expense_product_id=?");
			
			ps.setString(1, "C");
			ps.setString(2, strDate);
			ps.setString(3, expense_product_id);
			
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
	
	public void approve(String expense_product_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE expense_product set order_status=?, updated=? where expense_product_id=?");
			
			ps.setString(1, "A");
			ps.setString(2, strDate);
			ps.setString(3, expense_product_id);
			
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
	public void approveByMainExpense(String expense_id, String date_time){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE expense_product set order_status=?, updated=? where expense_id=? and date_time=?");
			
			ps.setString(1, "A");
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
	// set requisition_product order_status='A' based on requisition_multi id [E]
	
	public void expenseApproveByMainExpense(String expense_id, String date_time){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE expense_product set expense_status=?, updated=? where expense_id=? and date_time=?");
			
			ps.setString(1, "A");
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
	
	public void expenseCancel(String expense_product_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE expense_product set expense_status=?, updated=? where expense_product_id=?");
			
			ps.setString(1, "C");
			ps.setString(2, strDate);
			ps.setString(3, expense_product_id);
			
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
	
	public void expenseCaneclByMainExpense(String expense_id, String date_time){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE expense_product set expense_status=?, updated=? where expense_id=? and date_time=?");
			
			ps.setString(1, "C");
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
	
	// delivery return from sales product screen [S]
	public void expenseCancelByExpenseProduct(String expense_product_id, String expense_id, String date_time){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE expense_product set expense_status=?, updated=? where expense_product_id=? and expense_id=? and date_time=?");
			
			ps.setString(1, "C");
			ps.setString(2, strDate);
			ps.setString(3, expense_product_id);
			ps.setString(4, expense_id);
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
	
	public List<ExpenseProduct> getAllExpenseProduct(){
		List<ExpenseProduct> list = new ArrayList<ExpenseProduct>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT expense_product_id, expense_id, expense_type, date_time, category_id, category_name, quantity, price, total_price, discount_amt, total_amount, order_status, expense_status, created, updated, created_by, updated_by FROM expense_product ORDER BY created DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				ExpenseProduct ep = new ExpenseProduct();				
				
				ep.setExpense_product_id(rs.getString(1));
				ep.setExpense_id(rs.getString(2));
				ep.setExpense_type(rs.getString(3));
				ep.setDate_time(rs.getString(4));
				ep.setCategory_id(rs.getString(5));
				ep.setCategory_name(rs.getString(6));
				ep.setQuantity(rs.getInt(7));
				ep.setPrice(rs.getDouble(8));
				ep.setTotal_price(rs.getDouble(9));
				ep.setDiscount_amt(rs.getDouble(10));
				ep.setTotal_amount(rs.getDouble(11));
				ep.setOrder_status(rs.getString(12));
				ep.setExpense_status(rs.getString(13));
				ep.setCreated(rs.getString(14));
				ep.setUpdated(rs.getString(15));
				ep.setCreated_by(rs.getString(16));
				ep.setUpdated_by(rs.getString(17));
			
				list.add(ep);				
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
	
	public ExpenseProduct getExpenseProductById(String expense_product_id){
		ExpenseProduct ep = new ExpenseProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT expense_product_id, expense_id, expense_type, date_time, category_id, category_name, quantity, price, total_price, discount_amt, total_amount, order_status, expense_status, created, updated, created_by, updated_by FROM expense_product where expense_product_id=?");
			
			ps.setString(1, expense_product_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				ep.setExpense_product_id(rs.getString(1));
				ep.setExpense_id(rs.getString(2));
				ep.setExpense_type(rs.getString(3));
				ep.setDate_time(rs.getString(4));
				ep.setCategory_id(rs.getString(5));
				ep.setCategory_name(rs.getString(6));
				ep.setQuantity(rs.getInt(7));
				ep.setPrice(rs.getDouble(8));
				ep.setTotal_price(rs.getDouble(9));
				ep.setDiscount_amt(rs.getDouble(10));
				ep.setTotal_amount(rs.getDouble(11));
				ep.setOrder_status(rs.getString(12));
				ep.setExpense_status(rs.getString(13));
				ep.setCreated(rs.getString(14));
				ep.setUpdated(rs.getString(15));
				ep.setCreated_by(rs.getString(16));
				ep.setUpdated_by(rs.getString(17));
				
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

		return ep;
	}
	
	// generated auto increment id during add [S]
	public ExpenseProduct getExpenseProductID(){
		ExpenseProduct ep = new ExpenseProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT expense_product_id FROM expense_product");
			
			rs = ps.executeQuery();
			
			int expense_product_id = 0;
			
			if(rs.next() == false) {
				expense_product_id = 1000000000;
				expense_product_id = expense_product_id+1;
				ep.setExpense_product_id("EPDT" + String.valueOf(expense_product_id));
			} else {
				if(rs.last()) {
					String strExpenseProduct = rs.getString("expense_product_id");
					expense_product_id = Integer.parseInt(strExpenseProduct.replaceAll("[^0-9]", ""));
					expense_product_id = expense_product_id+1;
					ep.setExpense_product_id("EPDT" + String.valueOf(expense_product_id));
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
		
		return ep;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public ExpenseProduct getSelectedOtherID(String expense_product_id){
		ExpenseProduct ep = new ExpenseProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT expense_product_id, expense_id, expense_type, date_time, category_id, category_name, order_status, expense_status, quantity FROM expense_product WHERE expense_product_id=?");
			
			ps.setString(1, expense_product_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strExpenseProduct = rs.getString("expense_product_id");
				String strExpenseMain = rs.getString("expense_id");
				String strExpenseType = rs.getString("expense_type");
				String strDateTime = rs.getString("date_time");
				String strCategoryId = rs.getString("category_id");
				String strCategoryName = rs.getString("category_name");
				String strOrderStatus = rs.getString("order_status");
				String strExpenseStatus = rs.getString("expense_status");
				int intQuantity = rs.getInt("quantity");
				
				ep.setExpense_product_id(strExpenseProduct);
				ep.setExpense_id(strExpenseMain);
				ep.setExpense_type(strExpenseType);
				ep.setDate_time(strDateTime);
				ep.setCategory_id(strCategoryId);
				ep.setCategory_name(strCategoryName);
				ep.setOrder_status(strOrderStatus);
				ep.setExpense_status(strExpenseStatus);
				ep.setQuantity(intQuantity);
				
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
		
		return ep;
	}
	// selected other respective id during update [E]
	
	public List<ExpenseProduct> getAllExpenseProductByMainIdDateTime(String expense_id, String strDateTime){
		List<ExpenseProduct> list = new ArrayList<ExpenseProduct>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT expense_product_id, expense_id, expense_type, date_time, category_id, category_name, quantity, price, total_price, discount_amt, total_amount, order_status, expense_status, created, updated, created_by, updated_by FROM expense_product where expense_id=? and date_time=?");
			
			ps.setString(1, expense_id);
			ps.setString(2, strDateTime);
			
			rs = ps.executeQuery();
			
			while (rs.next()) {
				ExpenseProduct ep = new ExpenseProduct();				
				
				ep.setExpense_product_id(rs.getString(1));
				ep.setExpense_id(rs.getString(2));
				ep.setExpense_type(rs.getString(3));
				ep.setDate_time(rs.getString(4));
				ep.setCategory_id(rs.getString(5));
				ep.setCategory_name(rs.getString(6));
				ep.setQuantity(rs.getInt(7));
				ep.setPrice(rs.getDouble(8));
				ep.setTotal_price(rs.getDouble(9));
				ep.setDiscount_amt(rs.getDouble(10));
				ep.setTotal_amount(rs.getDouble(11));
				ep.setOrder_status(rs.getString(12));
				ep.setExpense_status(rs.getString(13));
				ep.setCreated(rs.getString(14));
				ep.setUpdated(rs.getString(15));
				ep.setCreated_by(rs.getString(16));
				ep.setUpdated_by(rs.getString(17));
			
				list.add(ep);				
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
	public ExpenseProduct sumTotalAmount(String expense_id, String date_time){
		ExpenseProduct sp = new ExpenseProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sum(total_amount) FROM expense_product where expense_id=? and date_time=?");
			
			ps.setString(1, expense_id);
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
	public ExpenseProduct sumTotalAmountBasedOnCancelStatus(String expense_id, String date_time){
		ExpenseProduct ep = new ExpenseProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sum(total_amount) FROM expense_product where expense_id=? and date_time=? and expense_status=?");
			
			ps.setString(1, expense_id);
			ps.setString(2, date_time);
			ps.setString(3, "C");
			
			rs = ps.executeQuery();
			
			if (rs.next()) {
				ep.setTotal_amount(rs.getDouble(1));
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
		
		return ep;
	}
	// after delivery  return insert into customer_transaction_main based on sales_product id, Requisition_id and date time [E]
	
	
	
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
	/*public ExpenseProduct getExpenseProductToTransactionProduct(String purchase_id, String date_time){
		ExpenseProduct ep = new ExpenseProduct();
		
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
				tpdao.ExpenseProductToTransactionProduct(strPurchaseProductId, strPurchaseId, strType, strDateTime, strProductId, strProductName, strPackType,
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
	}*/
	// after delivery  return insert into transaction_product one by one from a list based on purchase_product id and date time [E]
	
	// after delivery  return insert into customer_transaction_product based on sales_product id, Requisition_id and date time [S]
	/*public ExpenseProduct expenseProductToTransactionProduct(String purchase_product_id, String purchase_id, String date_time){
		ExpenseProduct pp = new ExpenseProduct();
		
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
				tpdao.ExpenseProductToTransactionProduct(strPurchaseProductId, strPurchaseId, strType, strDateTime, strProductId, strProductName, strPackType,
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
	}*/
	// after delivery  return insert into customer_transaction_product based on sales_product id, Requisition_id and date time [E]
	
}
