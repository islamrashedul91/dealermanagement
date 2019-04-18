package com.rashed.pharmacy.controller;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import com.google.zxing.WriterException;

import com.rashed.pharmacy.model.Requisition;
import com.rashed.pharmacy.dao.RequisitionDAO;
import com.rashed.pharmacy.model.Product;
import com.rashed.pharmacy.dao.ProductDAO;
import com.rashed.pharmacy.model.CustomerInfo;
import com.rashed.pharmacy.dao.CustomerInfoDAO;
import com.rashed.pharmacy.model.CustomerPurchase;
import com.rashed.pharmacy.dao.CustomerPurchaseDAO;
import com.rashed.pharmacy.util.*;

public class CustomerPurchaseController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/order/customerPurchaseAdd.jsp";
	private static String LIST_CUSTOMERPURCHASE = "/jsp/order/customerPurchaseList.jsp";
	private static String ENQUIRY = "/jsp/order/customerPurchaseEnquiry.jsp";
	
	private RequisitionDAO rdao;
	private ProductDAO pdao;
	private CustomerInfoDAO cdao;
	private CustomerPurchaseDAO cpdao;
	
	String action = "";
	String message = "";
	
       
    public CustomerPurchaseController() {
        super();
        rdao = new RequisitionDAO();
        pdao = new ProductDAO();
        cdao = new CustomerInfoDAO();
        cpdao = new CustomerPurchaseDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String purchase_id = request.getParameter("purchase_id");
			cpdao.delete(purchase_id);
			forward=LIST_CUSTOMERPURCHASE;
			request.setAttribute("customerPurchases", cpdao.getAllCustomerPurchase());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String purchase_id = request.getParameter("purchase_id");
			CustomerPurchase cp = cpdao.getCustomerPurchaseById(purchase_id);
			request.setAttribute("customerPurchase", cp);
			// for get all the Requisition_id when update sales [S]
			request.setAttribute("allRequisition", rdao.getAllRequisition());
			// for get all the Requisition_id when update sales [E]
			// for get all the Product_id when update sales [S]
			request.setAttribute("allProduct", pdao.getAllProduct());
			// for get all the Product_id when update sales [E]
			// for get all the Customer when update sales [S]
			request.setAttribute("allCustomer", cdao.getAllCustomerInfo());
			// for get all the Customer when update sales [E]
			
			// selected other respective id during update [S]
			request.setAttribute("selectedRequisitionId", cpdao.getSelectedOtherID(purchase_id).getRequisition_id());
			request.setAttribute("selectedCustomerId", cpdao.getSelectedOtherID(purchase_id).getCustomer_id());
			request.setAttribute("selectedProductId", cpdao.getSelectedOtherID(purchase_id).getProduct_id());
			request.setAttribute("selectedBonusId", cpdao.getSelectedOtherID(purchase_id).getBonus_id());
			request.setAttribute("selectedSalesmanId", cpdao.getSelectedOtherID(purchase_id).getSalesman_id());
			// selected other respective id during update [E]
		} else if(action.equalsIgnoreCase("customerPurchaseList")){
			forward = LIST_CUSTOMERPURCHASE;
			request.setAttribute("customerPurchases", cpdao.getAllCustomerPurchase());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String purchase_id = request.getParameter("purchase_id");
			CustomerPurchase cp = cpdao.getCustomerPurchaseById(purchase_id);
			request.setAttribute("customerPurchase", cp);
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("purchaseId", cpdao.getCustomerPurchaseID().getPurchase_id());
			// generated auto increment id during add [E]
			
			// for get all the Requisition_id when add sales [S]
			request.setAttribute("allRequisition", rdao.getAllRequisition());
			// for get all the Requisition_id when add sales [E]
			// for get all the Product_id when add sales [S]
			request.setAttribute("allProduct", pdao.getAllProduct());
			// for get all the Product_id when add sales [E]
			// for get all the Customer when add sales [S]
			request.setAttribute("allCustomer", cdao.getAllCustomerInfo());
			// for get all the Customer when add sales [E]
			
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		CustomerPurchase cp = new CustomerPurchase();
		
		cp.setPurchase_id(request.getParameter("purchase_id"));
		cp.setPurchase_type(request.getParameter("purchase_type"));
		cp.setRequisition_id(request.getParameter("requisition_id"));
		cp.setCustomer_id(request.getParameter("customer_id"));
		cp.setCustomer_name(request.getParameter("customer_name"));
		cp.setMobile(request.getParameter("mobile"));
		cp.setProduct_id(request.getParameter("product_id"));
		cp.setProduct_name(request.getParameter("product_name"));
		cp.setPack_type(request.getParameter("pack_type"));
		cp.setPack_size(request.getParameter("pack_size"));
		cp.setPiceces(Integer.parseInt(request.getParameter("piceces")));
		cp.setBonus_id(request.getParameter("bonus_id"));
		cp.setBonus_name(request.getParameter("bonus_name"));
		cp.setOrder_pack(request.getParameter("order_pack"));
		cp.setOrder_quantity(Integer.parseInt(request.getParameter("order_quantity")));
		cp.setMrp_price(Double.parseDouble(request.getParameter("mrp_price")));
		cp.setTotal_mrp_price(Double.parseDouble(request.getParameter("total_mrp_price")));
		cp.setDiscount_amt(Double.parseDouble(request.getParameter("discount_amt")));
		cp.setTotal_amount(Double.parseDouble(request.getParameter("total_amount")));
		cp.setNeeded_date_time(request.getParameter("needed_date_time"));
		cp.setFrom_account_id(request.getParameter("from_account_id"));
		cp.setTo_account_id(request.getParameter("to_account_id"));
		cp.setSalesman_id(request.getParameter("salesman_id"));
		cp.setOrder_status(request.getParameter("order_status"));
		cp.setDelivery_status(request.getParameter("delivery_status"));
		cp.setCreated(request.getParameter("created"));
		cp.setUpdated(request.getParameter("updated"));
		cp.setCreated_by(request.getParameter("created_by"));
		cp.setUpdated_by(request.getParameter("updated_by"));
	
		String purchase_id = request.getParameter("purchase_id");

		if(action.equalsIgnoreCase("save")){
			cpdao.save(cp);
		} else if(action.equalsIgnoreCase("edit")){
			cp.setPurchase_id(purchase_id);
			cpdao.update(cp);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_CUSTOMERPURCHASE);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("customerPurchases", cpdao.getAllCustomerPurchase());
		
		rd.forward(request, response);
	}

}
