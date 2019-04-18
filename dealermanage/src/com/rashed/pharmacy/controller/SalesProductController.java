package com.rashed.pharmacy.controller;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.websocket.Session;

import com.google.zxing.WriterException;
import com.rashed.pharmacy.model.CustomerTransactionMain;
import com.rashed.pharmacy.model.SalesProduct;
import com.rashed.pharmacy.dao.CustomerTransactionMainDAO;
import com.rashed.pharmacy.dao.SalesProductDAO;
import com.rashed.pharmacy.model.RequisitionProduct;
import com.rashed.pharmacy.dao.RequisitionProductDAO;
import com.rashed.pharmacy.model.RequisitionMulti;
import com.rashed.pharmacy.dao.RequisitionMultiDAO;
import com.rashed.pharmacy.model.Product;
import com.rashed.pharmacy.dao.ProductDAO;
import com.rashed.pharmacy.model.CustomerInfo;
import com.rashed.pharmacy.dao.CustomerInfoDAO;
import com.rashed.pharmacy.model.Sales;
import com.rashed.pharmacy.dao.SalesDAO;
import com.rashed.pharmacy.model.SalesmanInfo;
import com.rashed.pharmacy.dao.SalesmanInfoDAO;
import com.rashed.pharmacy.model.SalesMain;
import com.rashed.pharmacy.dao.SalesMainDAO;
import com.rashed.pharmacy.util.*;

public class SalesProductController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/order/salesProductAdd.jsp";
	private static String LIST_SALESPRODUCT = "/jsp/order/salesProductList.jsp";
	private static String ENQUIRY = "/jsp/order/salesProductEnquiry.jsp";
	
	private RequisitionProductDAO rpdao;
	private ProductDAO pdao;
	private CustomerInfoDAO cdao;
	private SalesDAO sdao;
	private SalesmanInfoDAO smdao;
	private RequisitionMultiDAO rmdao;
	private SalesProductDAO spdao;
	private SalesMainDAO smmdao;
	private CustomerTransactionMainDAO ctmdao;
	
	String action = "";
	String message = "";
	
       
    public SalesProductController() {
        super();
        rpdao = new RequisitionProductDAO();
        pdao = new ProductDAO();
        cdao = new CustomerInfoDAO();
        sdao = new SalesDAO();
        smdao = new SalesmanInfoDAO();
        rmdao = new RequisitionMultiDAO();
        spdao = new SalesProductDAO();
        smmdao = new SalesMainDAO();
        ctmdao = new CustomerTransactionMainDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String sales_product_id = request.getParameter("sales_product_id");
			//rpdao.delete(requisition_product_id);
			String strOrderStatus = spdao.getSelectedOtherID(sales_product_id).getOrder_status();
			if (!strOrderStatus.equals("A")) {
				spdao.delete(sales_product_id);
				message = "Sales " + sales_product_id + " deleted Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Approved Sales can not be deleted !!!";
				request.setAttribute("success", message);
			}
			forward=LIST_SALESPRODUCT;
			request.setAttribute("salesProducts", spdao.getAllSalesProduct());
			/*message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);*/
		} else if(action.equalsIgnoreCase("cancel")){
			String sales_product_id = request.getParameter("sales_product_id");
			String strOrderStatus = spdao.getSelectedOtherID(sales_product_id).getOrder_status();
			String strProduct = spdao.getSelectedOtherID(sales_product_id).getProduct_id();
			String strRequisition = spdao.getSelectedOtherID(sales_product_id).getRequisition_id();
			int intOrderQuantity = spdao.getSelectedOtherID(sales_product_id).getOrder_quantity();
			
			if (!strOrderStatus.equals("S")) {
				spdao.cancel(sales_product_id);
				
				/*pdao.returnStockUpdate(strProduct, intOrderQuantity);
				
				ctdao.salesToCustomerTransaction(sales_product_id, action);
				
				rdao.delete(strRequisition);
				
				sdao.delete(sales_product_id);*/
				
				message = "Sales " + sales_product_id + " Cancelled Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Success Sales can not be cancelled !!!";
				request.setAttribute("success", message);
			}
			
			forward=LIST_SALESPRODUCT;
			request.setAttribute("salesProducts", spdao.getAllSalesProduct());
		} else if(action.equalsIgnoreCase("approve")){
			String sales_product_id = request.getParameter("sales_product_id");
			String strOrderStatus = spdao.getSelectedOtherID(sales_product_id).getOrder_status();
			String strProduct = spdao.getSelectedOtherID(sales_product_id).getProduct_id();
			int intOrderQuantity = spdao.getSelectedOtherID(sales_product_id).getOrder_quantity();
			if (!strOrderStatus.equals("S") && !strOrderStatus.equals("C")) {
				spdao.approve(sales_product_id);
				
				//Sales s = new Sales();
				/*sdao.requisitionToSales(requisition_product_id);
				
				pdao.stockUpdate(strProduct, intOrderQuantity);*/
				
				message = "Sales " + sales_product_id + " Approved Successfully!!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Cancelled Sales can not be Approved !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("S")) {
					message = "Already Success !!!";
					request.setAttribute("success", message);
				}
			}
			
			forward=LIST_SALESPRODUCT;
			request.setAttribute("salesProducts", spdao.getAllSalesProduct());
		} else if(action.equalsIgnoreCase("deliveryReturn")){
			String sales_product_id = request.getParameter("sales_product_id");
			//String sales_id = request.getParameter("sales_id");
			String strSales = spdao.getSelectedOtherID(sales_product_id).getSales_id();
			String strSalesType = spdao.getSelectedOtherID(sales_product_id).getSales_type();
			String strProduct = spdao.getSelectedOtherID(sales_product_id).getProduct_id();
			int intOrderQuantity = spdao.getSelectedOtherID(sales_product_id).getOrder_quantity();
			String strOrderStatus = spdao.getSelectedOtherID(sales_product_id).getOrder_status();
			String strDeliveryStatus = spdao.getSelectedOtherID(sales_product_id).getDelivery_status();
			String strRequisition = spdao.getSelectedOtherID(sales_product_id).getRequisition_id();
			String date_time = spdao.getSelectedOtherID(sales_product_id).getDate_time();
			double doubleTotalAmount = spdao.getSelectedOtherID(sales_product_id).getTotal_amount();
			
			if (strOrderStatus.equals("S") && !strDeliveryStatus.equals("D") && !strDeliveryStatus.equals("C") && !strDeliveryStatus.equals("R")) {
				
				spdao.deliveryReturnBySalesProduct(sales_product_id, strRequisition, date_time);
				
				String strTransactionID = ctmdao.getCustomerTransactionMainByIdDateTime(strRequisition, date_time).getTransaction_id();
				if(strTransactionID == null || strTransactionID.equals("")){
					ctmdao.productSalesMainToCustomerTransactionMain(strRequisition, date_time);
				} else if(strTransactionID != null && !strTransactionID.equals("")){
					ctmdao.returnTotalAmount(strRequisition, date_time);
				}
				//ctmdao.productSalesMainToCustomerTransactionMain(strRequisition, date_time);
				
				//spdao.getSalesProductToCustomerTransactionProduct(strRequisition, date_time);
				spdao.salesProductToCustomerTransactionProduct(sales_product_id, strRequisition, date_time);
				
				//spdao.getProdcutIdForStockUpdate(strRequisition, date_time);
				pdao.returnStockUpdate(strProduct, intOrderQuantity);
				
				// Sales Type not equals Manual then record deleted from Requisition table, because Manual sales don't have any requisition [S]
				/*if(!strSalesType.equals("Manual")){
					rpdao.deleteByIdDateTime(strRequisition, date_time);
					rmdao.deleteByIdDateTime(strRequisition, date_time);
				}*/
				// Sales Type not equals Manual then record deleted from Requisition table, because Manual sales don't have any requisition [E]
				
				spdao.deleteBySPIdRIdDateTime(sales_product_id, strRequisition, date_time);
				
				message = "Sales " + sales_product_id + " Delivery Return !!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Sales Already Cancelled !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A")) {
					message = "Without Success Sales can not be Delivered !!!";
					request.setAttribute("success", message);
				} else if (strDeliveryStatus.equals("C")) {
					message = "Delivery Already Cancelled !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("S") && strDeliveryStatus.equals("D")) {
					message = "Already Delivered !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("S") && strDeliveryStatus.equals("R")) {
					message = "Already Return !!!";
					request.setAttribute("success", message);
				}
			}
			forward=LIST_SALESPRODUCT;

			request.setAttribute("salesProducts", spdao.getAllSalesProductByMainIdDateTime(strSales, strRequisition, date_time));
			
			request.setAttribute("sales_id", strSales);
			request.setAttribute("sales_type", strSalesType);
			request.setAttribute("requisition_id", strRequisition);
			request.setAttribute("strDateTime", date_time);
			request.setAttribute("customer_name", request.getParameter("customer_name"));
			request.setAttribute("mobile", request.getParameter("mobile"));
			
			request.setAttribute("sumTotalAmount", spdao.sumTotalAmount(strSales, strRequisition, date_time).getTotal_amount());
			
			smmdao.sumTotalAmountSP(strSales, strRequisition, date_time);
			
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String sales_product_id = request.getParameter("sales_product_id");
			SalesProduct sp = spdao.getSalesProductById(sales_product_id);
			request.setAttribute("salesProduct", sp);
			// for get all the Product_id when update requisition [S]
			request.setAttribute("allProduct", pdao.getAllProduct());
			// for get all the Product_id when update requisition [E]
			// for get all the Customer when update requisition [S]
			/*request.setAttribute("allCustomer", cdao.getAllCustomerInfo());*/
			// for get all the Customer when update requisition [E]
			// for get all the Salesman when update requisition [S]
			/*request.setAttribute("allSalesman", smdao.getAllSalesmanInfo());*/
			// for get all the Salesman when update requisition [E]
			
			// selected other respective id during update [S]
			/*request.setAttribute("selectedCustomerId", rpdao.getSelectedOtherID(requisition_product_id).getCustomer_id());*/
			request.setAttribute("selectedProductId", spdao.getSelectedOtherID(sales_product_id).getProduct_id());
			request.setAttribute("selectedBonusId", spdao.getSelectedOtherID(sales_product_id).getBonus_id());
			/*request.setAttribute("selectedSalesmanId", rpdao.getSelectedOtherID(requisition_product_id).getSalesman_id());*/
			// selected other respective id during update [E]
			
			// get value from Multi Requisition [S]
			/*request.setAttribute("requisition_multi_id1", requisition_multi_id);
			request.setAttribute("strDateTimeMulti1", strDateTimeMulti);
			request.setAttribute("customerNameMulti1", customerNameMulti);
			request.setAttribute("customerMobileMulti1", customerMobileMulti);*/
			// get value from Multi Requisition [S]
		} else if(action.equalsIgnoreCase("salesProductList")){
			forward = LIST_SALESPRODUCT;
			request.setAttribute("salesProducts", spdao.getAllSalesProduct());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String sales_product_id = request.getParameter("sales_product_id");
			SalesProduct sp = spdao.getSalesProductById(sales_product_id);
			request.setAttribute("salesProduct", sp);
		} else if(action.equalsIgnoreCase("enquiryEnquiry")){
			forward = ENQUIRY;
			String sales_product_id = request.getParameter("sales_product_id");
			SalesProduct sp = spdao.getSalesProductById(sales_product_id);
			request.setAttribute("salesProduct", sp);
		} else {
			forward = INSERT_OR_EDIT;
			// get value from Multi Requisition [S]
			/*request.setAttribute("requisition_multi_id1", requisition_multi_id);
			request.setAttribute("strDateTimeMulti1", strDateTimeMulti);
			request.setAttribute("customerNameMulti1", customerNameMulti);
			request.setAttribute("customerMobileMulti1", customerMobileMulti);*/
			// get value from Multi Requisition [S]
			
			// generated auto increment id during add [S]
			request.setAttribute("salesProductId", spdao.getSalesProductID().getSales_product_id());
			// generated auto increment id during add [E]
			// for manual salesProduct requisitionProduct id [S]
			request.setAttribute("requisitionProductId", rpdao.getRequisitionProductID().getRequisition_product_id());
			// for manual salesProduct requisitionProduct id [E]
			
			// for get all the Product_id when add requisition [S]
			request.setAttribute("allProduct", pdao.getAllProduct());
			// for get all the Product_id when add requisition [E]
			// for get all the Customer when add requisition [S]
			/*request.setAttribute("allCustomer", cdao.getAllCustomerInfo());*/
			// for get all the Customer when add requisition [E]
			// for get all the Salesman when ad requisition [S]
			/*request.setAttribute("allSalesman", smdao.getAllSalesmanInfo());*/
			// for get all the Salesman when add requisition [E]
			
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		SalesProduct sp = new SalesProduct();
		
		sp.setSales_product_id(request.getParameter("sales_product_id"));
		sp.setSales_id(request.getParameter("sales_id"));
		sp.setSales_type("sales_type");
		sp.setRequisition_product_id(request.getParameter("requisition_product_id"));
		sp.setRequisition_id(request.getParameter("requisition_id"));
		sp.setDate_time(request.getParameter("date_time"));
		sp.setProduct_id(request.getParameter("product_id"));
		sp.setProduct_name(request.getParameter("product_name"));
		sp.setPack_type(request.getParameter("pack_type"));
		sp.setPack_size(request.getParameter("pack_size"));
		sp.setPiceces(Integer.parseInt(request.getParameter("piceces")));
		sp.setBonus_id(request.getParameter("bonus_id"));
		sp.setBonus_name(request.getParameter("bonus_name"));
		sp.setOrder_pack(request.getParameter("order_pack"));
		sp.setOrder_quantity(Integer.parseInt(request.getParameter("order_quantity")));
		sp.setMrp_price(Double.parseDouble(request.getParameter("mrp_price")));
		sp.setTotal_mrp_price(Double.parseDouble(request.getParameter("total_mrp_price")));
		sp.setDiscount_amt(Double.parseDouble(request.getParameter("discount_amt")));
		sp.setTotal_amount(Double.parseDouble(request.getParameter("total_amount")));
		sp.setOrder_status(request.getParameter("order_status"));
		sp.setDelivery_status(request.getParameter("delivery_status"));
		sp.setCreated(request.getParameter("created"));
		sp.setUpdated(request.getParameter("updated"));
		sp.setCreated_by(request.getParameter("created_by"));
		sp.setUpdated_by(request.getParameter("updated_by"));
	
		String sales_product_id = request.getParameter("sales_product_id");
		String sales_id = request.getParameter("sales_id");
		String requisition_product_id = request.getParameter("requisition_product_id");
		String requisition_id = request.getParameter("requisition_id");
		String strDateTime = request.getParameter("date_time");

		if(action.equalsIgnoreCase("save")){
			spdao.save(sp);
		} else if(action.equalsIgnoreCase("edit")){
			sp.setSales_product_id(sales_product_id);
			spdao.update(sp);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_SALESPRODUCT);
		request.setAttribute("salesProducts", spdao.getAllSalesProductByMainIdDateTime(sales_id, requisition_id, strDateTime));
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		/*request.setAttribute("requisitionProducts", rpdao.getAllRequisitionProduct());*/
		// for transfer data into another page (Product Requisition) [S]
		HttpSession session1 = request.getSession();
		
		request.setAttribute("sales_id", request.getParameter("sales_id"));
		request.setAttribute("requisition_id", request.getParameter("requisition_id"));
		request.setAttribute("strDateTime", request.getParameter("date_time"));
		request.setAttribute("customer_name", smmdao.getSalesMainByIdDateTime(requisition_id, strDateTime).getCustomer_name());
		request.setAttribute("mobile", smmdao.getSalesMainByIdDateTime(requisition_id, strDateTime).getMobile());
		// for transfer data into another page (Product Requisition) [E]
		// for Requisition Product sum total amount [S]
		request.setAttribute("sumTotalAmount", spdao.sumTotalAmount(sales_id, requisition_id, strDateTime).getTotal_amount());
		// for Requisition Product sum total amount [E]
		
		// for insert into requisition_multi total_amount from Requisition Product sum total amount [S]
		smmdao.sumTotalAmountSP(sales_id, requisition_id, strDateTime);
		// for insert into requisition_multi total_amount from Requisition Product sum total amount [E]
		
		rd.forward(request, response);
	}

}
