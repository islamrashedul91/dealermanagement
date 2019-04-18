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
import com.rashed.pharmacy.util.*;

public class RequisitionProductController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/order/requisitionProductAdd.jsp";
	private static String LIST_REQUISITIONPRODUCT = "/jsp/order/requisitionProductList.jsp";
	private static String ENQUIRY = "/jsp/order/requisitionProductEnquiry.jsp";
	
	private RequisitionProductDAO rpdao;
	private ProductDAO pdao;
	private CustomerInfoDAO cdao;
	private SalesDAO sdao;
	private SalesmanInfoDAO smdao;
	private RequisitionMultiDAO rmdao;
	
	String action = "";
	String message = "";
	
       
    public RequisitionProductController() {
        super();
        rpdao = new RequisitionProductDAO();
        pdao = new ProductDAO();
        cdao = new CustomerInfoDAO();
        sdao = new SalesDAO();
        smdao = new SalesmanInfoDAO();
        rmdao = new RequisitionMultiDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		// get value from Multi Requisition [S]
		String requisition_multi_id = request.getParameter("requisition_multi_id");
		String strDateTimeMulti = request.getParameter("strDateTimeMulti");
		String customerNameMulti = request.getParameter("customerNameMulti");
		String customerMobileMulti = request.getParameter("customerMobileMulti");
		// get value from Multi Requisition [E]
		
		if(action.equalsIgnoreCase("delete")){
			String requisition_product_id = request.getParameter("requisition_product_id");
			//rpdao.delete(requisition_product_id);
			String strOrderStatus = rpdao.getSelectedOtherID(requisition_product_id).getOrder_status();
			if (!strOrderStatus.equals("A")) {
				rpdao.delete(requisition_product_id);
				message = "Order " + requisition_product_id + " deleted Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Approved Order can not be deleted !!!";
				request.setAttribute("success", message);
			}
			forward=LIST_REQUISITIONPRODUCT;
			request.setAttribute("requisitionProducts", rpdao.getAllRequisitionProduct());
			/*message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);*/
		} else if(action.equalsIgnoreCase("cancel")){
			String requisition_product_id = request.getParameter("requisition_product_id");
			String strOrderStatus = rpdao.getSelectedOtherID(requisition_product_id).getOrder_status();
			if (!strOrderStatus.equals("A")) {
				rpdao.cancel(requisition_product_id);
				message = "Order " + requisition_product_id + " Cancelled Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Approved Order can not be cancelled !!!";
				request.setAttribute("success", message);
			}
			forward=LIST_REQUISITIONPRODUCT;
			request.setAttribute("requisitionProducts", rpdao.getAllRequisitionProduct());
		} else if(action.equalsIgnoreCase("approve")){
			String requisition_product_id = request.getParameter("requisition_product_id");
			String strOrderStatus = rpdao.getSelectedOtherID(requisition_product_id).getOrder_status();
			String strProduct = rpdao.getSelectedOtherID(requisition_product_id).getProduct_id();
			int intOrderQuantity = rpdao.getSelectedOtherID(requisition_product_id).getOrder_quantity();
			if (!strOrderStatus.equals("A") && !strOrderStatus.equals("C")) {
				rpdao.approve(requisition_product_id);
				
				//Sales s = new Sales();
				/*sdao.requisitionToSales(requisition_product_id);
				
				pdao.stockUpdate(strProduct, intOrderQuantity);*/
				
				message = "Order " + requisition_product_id + " Approved Successfully!!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Cancelled Order can not be Approved !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A")) {
					message = "Already Approved !!!";
					request.setAttribute("success", message);
				}
			}
			forward=LIST_REQUISITIONPRODUCT;
			request.setAttribute("requisitionProducts", rpdao.getAllRequisitionProduct());
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String requisition_product_id = request.getParameter("requisition_product_id");
			RequisitionProduct rp = rpdao.getRequisitionProductById(requisition_product_id);
			request.setAttribute("requisitionProduct", rp);
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
			request.setAttribute("selectedProductId", rpdao.getSelectedOtherID(requisition_product_id).getProduct_id());
			request.setAttribute("selectedBonusId", rpdao.getSelectedOtherID(requisition_product_id).getBonus_id());
			/*request.setAttribute("selectedSalesmanId", rpdao.getSelectedOtherID(requisition_product_id).getSalesman_id());*/
			// selected other respective id during update [E]
			
			// get value from Multi Requisition [S]
			request.setAttribute("requisition_multi_id1", requisition_multi_id);
			request.setAttribute("strDateTimeMulti1", strDateTimeMulti);
			request.setAttribute("customerNameMulti1", customerNameMulti);
			request.setAttribute("customerMobileMulti1", customerMobileMulti);
			// get value from Multi Requisition [S]
		} else if(action.equalsIgnoreCase("requisitionProductList")){
			forward = LIST_REQUISITIONPRODUCT;
			request.setAttribute("requisitionProducts", rpdao.getAllRequisitionProduct());
			// test
			request.setAttribute("test1", request.getAttribute("test"));
			// test
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String requisition_product_id = request.getParameter("requisition_product_id");
			RequisitionProduct rp = rpdao.getRequisitionProductById(requisition_product_id);
			request.setAttribute("requisitionProduct", rp);
		} else if(action.equalsIgnoreCase("enquiryEnquiry")){
			forward = ENQUIRY;
			String requisition_product_id = request.getParameter("requisition_product_id");
			RequisitionProduct rp = rpdao.getRequisitionProductById(requisition_product_id);
			request.setAttribute("requisitionProduct", rp);
		} else {
			forward = INSERT_OR_EDIT;
			// get value from Multi Requisition [S]
			/*request.setAttribute("requisition_multi_id1", requisition_multi_id);
			request.setAttribute("strDateTimeMulti1", strDateTimeMulti);
			request.setAttribute("customerNameMulti1", customerNameMulti);
			request.setAttribute("customerMobileMulti1", customerMobileMulti);*/
			// get value from Multi Requisition [S]
			
			// generated auto increment id during add [S]
			request.setAttribute("requisitionProductId", rpdao.getRequisitionProductID().getRequisition_product_id());
			// generated auto increment id during add [E]
			
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
		
		RequisitionProduct rp = new RequisitionProduct();
		
		rp.setRequisition_product_id(request.getParameter("requisition_product_id"));
		rp.setRequisition_id(request.getParameter("requisition_id"));
		rp.setDate_time(request.getParameter("date_time"));
		rp.setProduct_id(request.getParameter("product_id"));
		rp.setProduct_name(request.getParameter("product_name"));
		rp.setPack_type(request.getParameter("pack_type"));
		rp.setPack_size(request.getParameter("pack_size"));
		rp.setPiceces(Integer.parseInt(request.getParameter("piceces")));
		rp.setBonus_id(request.getParameter("bonus_id"));
		rp.setBonus_name(request.getParameter("bonus_name"));
		rp.setOrder_pack(request.getParameter("order_pack"));
		rp.setOrder_quantity(Integer.parseInt(request.getParameter("order_quantity")));
		rp.setMrp_price(Double.parseDouble(request.getParameter("mrp_price")));
		rp.setTotal_mrp_price(Double.parseDouble(request.getParameter("total_mrp_price")));
		rp.setDiscount_amt(Double.parseDouble(request.getParameter("discount_amt")));
		rp.setTotal_amount(Double.parseDouble(request.getParameter("total_amount")));
		rp.setOrder_status(request.getParameter("order_status"));
		rp.setDelivery_status(request.getParameter("delivery_status"));
		rp.setCreated(request.getParameter("created"));
		rp.setUpdated(request.getParameter("updated"));
	
		String requisition_product_id = request.getParameter("requisition_product_id");
		String requisition_id = request.getParameter("requisition_id");
		String strDateTime = request.getParameter("date_time");

		if(action.equalsIgnoreCase("save")){
			rpdao.save(rp);
		} else if(action.equalsIgnoreCase("edit")){
			rp.setRequisition_product_id(requisition_product_id);
			rpdao.update(rp);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_REQUISITIONPRODUCT);
		request.setAttribute("requisitionProducts", rpdao.getAllRequisitionProductByMultiId(requisition_id, strDateTime));
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
		
		request.setAttribute("requisition_multi_id", request.getParameter("requisition_id"));
		request.setAttribute("strDateTimeMulti", request.getParameter("date_time"));
		request.setAttribute("customerNameMulti", rmdao.getRequisitionMultiByIdDateTime(requisition_id, strDateTime).getCustomer_name());
		request.setAttribute("customerMobileMulti", rmdao.getRequisitionMultiByIdDateTime(requisition_id, strDateTime).getMobile());
		// for transfer data into another page (Product Requisition) [E]
		// for Requisition Product sum total amount [S]
		request.setAttribute("sumTotalAmount", rpdao.sumTotalAmount(requisition_id, strDateTime).getTotal_amount());
		// for Requisition Product sum total amount [E]
		
		// for insert into requisition_multi total_amount from Requisition Product sum total amount [S]
		rmdao.sumTotalAmountRP(requisition_id, strDateTime);
		// for insert into requisition_multi total_amount from Requisition Product sum total amount [E]
		
		rd.forward(request, response);
	}

}
