package com.rashed.pharmacy.controller;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.zxing.WriterException;
import com.rashed.pharmacy.model.OwnerInfo;
import com.rashed.pharmacy.dao.AccountDAO;
import com.rashed.pharmacy.dao.OwnerInfoDAO;
import com.rashed.pharmacy.util.*;

public class OwnerInfoController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/owner/ownerInfoAdd.jsp";
	private static String LIST_OWNERINFO = "/jsp/owner/ownerInfoList.jsp";
	private static String ENQUIRY = "/jsp/owner/ownerInfoEnquiry.jsp";
	
	private OwnerInfoDAO dao;
	private AccountDAO adao;
	
	String action = "";
	String message = "";
	
       
    public OwnerInfoController() {
        super();
        dao = new OwnerInfoDAO();
        adao = new AccountDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			//int id=Integer.parseInt(request.getParameter("id"));
			String owner_id = request.getParameter("owner_id");
			dao.delete(owner_id);
			forward=LIST_OWNERINFO;
			request.setAttribute("ownerInfos", dao.getAllOwnerInfo());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String owner_id = request.getParameter("owner_id");
			OwnerInfo oi = dao.getOwnerInfoById(owner_id);
			request.setAttribute("ownerInfo", oi);
		} else if(action.equalsIgnoreCase("ownerInfoList")){
			forward = LIST_OWNERINFO;
			request.setAttribute("ownerInfos", dao.getAllOwnerInfo());
		}  else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String owner_id = request.getParameter("owner_id");
			OwnerInfo oi = dao.getOwnerInfoById(owner_id);
			request.setAttribute("ownerInfo", oi);
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("ownerId", dao.getOwnerInfoID().getOwner_id());
			// generated auto increment id during add [E]
			// for get MAIN Account ID [S]
			request.setAttribute("mainAccountId", adao.getMainAccount().getAccount_id());
			// for get MAIN Account ID [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		OwnerInfo oi = new OwnerInfo();
		
		oi.setOwner_id(request.getParameter("owner_id"));
		oi.setOwner_name(request.getParameter("owner_name"));
		oi.setDescription(request.getParameter("description"));
		oi.setOwner_type(request.getParameter("owner_type"));
		oi.setOwner_start_date(request.getParameter("owner_start_date"));
		oi.setFather_name(request.getParameter("father_name"));
		oi.setMother_name(request.getParameter("mother_name"));
		oi.setNid(request.getParameter("nid"));
		oi.setDob(request.getParameter("dob"));
		oi.setOccupation(request.getParameter("occupation"));
		oi.setCountry_id(request.getParameter("country_id"));
		oi.setMobile(request.getParameter("mobile"));
		oi.setEmail(request.getParameter("email"));
		oi.setAccount_id(request.getParameter("account_id"));
		oi.setHome_address(request.getParameter("home_address"));
		oi.setOffice_address(request.getParameter("office_address"));
		oi.setProfession(request.getParameter("profession"));
		if(action.equalsIgnoreCase("save")){
			oi.setPassword(request.getParameter("password"));
		}
		oi.setStatus(request.getParameter("status"));
		oi.setCreated(request.getParameter("created"));
		oi.setUpdated(request.getParameter("updated"));
		
		String owner_id = request.getParameter("owner_id");
		String owner_name = request.getParameter("owner_name");
		//String message = "Success!";
		if(action.equalsIgnoreCase("save")){
			dao.save(oi);
		} else if(action.equalsIgnoreCase("edit")){
			oi.setOwner_id(owner_id);
			dao.update(oi);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_OWNERINFO);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("ownerInfos", dao.getAllOwnerInfo());
		
		rd.forward(request, response);
	}

}
