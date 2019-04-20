<jsp:include page="../../base.jsp"></jsp:include>
<br>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="java.util.Date" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Online Pharmacy</title>
<link rel="stylesheet" 	href="${pageContext.request.contextPath}/css/table.css">

<script language="JavaScript">

/* function customerChng() {
	oSelectOne = frmSave.elements["brand_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalText = split_selected_option_text[1];
	
	document.getElementById('brand_name').value = finalText;

} */

function customerChng() {
	oSelectOne = frmSave.elements["customer_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalTextName = split_selected_option_text[1];
	var finalTextMobile = split_selected_option_text[2];
	
	document.getElementById('customer_name').value = finalTextName;
	document.getElementById('mobile').value = finalTextMobile;

}

function productChng() {
	oSelectOne = frmSave.elements["product_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalTextName = split_selected_option_text[1];
	var finalTextType = split_selected_option_text[2];
	var finalTextSize = split_selected_option_text[3];
	var finalTextPieces = split_selected_option_text[4];
	var finalTextMRP = split_selected_option_text[5];
	
	document.getElementById('product_name').value = finalTextName;
	document.getElementById('pack_type').value = finalTextType;
	document.getElementById('pack_size').value = finalTextSize;
	document.getElementById('piceces').value = finalTextPieces;
	document.getElementById('mrp_price').value = finalTextMRP;

}

function bonusChng() {
	oSelectOne = frmSave.elements["bonus_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalText = split_selected_option_text[1];
	
	document.getElementById('bonus_name').value = finalText;

}

function quantityToTotalMRP() {
	
	var quantity = document.getElementById('order_quantity').value;
	var mrp = document.getElementById('mrp_price').value;
	var quantityMultiplyMrp = quantity * mrp;
	
	//document.getElementById('total_mrp_price').value = quantityMultiplyMrp;
	document.getElementById('total_mrp_price').value = quantityMultiplyMrp.toFixed(2);

}

function discountToTotalAmount() {
	
	var discount = document.getElementById('discount_amt').value;
	var totalMrp = document.getElementById('total_mrp_price').value;
	var totalMrpMinusDiscount = totalMrp - discount;
	
	//document.getElementById('total_amount').value = totalMrpMinusDiscount;
	document.getElementById('total_amount').value = totalMrpMinusDiscount.toFixed(2);

}

</script>

</head>
<body>
<%
String action = (String) session.getAttribute("action");
System.out.println("++++++"+action);
%>
<div class="mcontent">
			<div class="titlenav">
				<ul>					
					<li class="title"><a href="">
					<%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Multi Requisition Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Multi Requisition Update</td>
					<%
					}
					%>
					</a></li>
					<li class="bread"><a href="">Dashboard > Order Management > Multi Requisition List > <%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Multi Requisition Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Multi Requisition Update</td>
					<%
					}
					%></a></li>
				</ul>
			</div>
			<br>
		<div class="card">
			<div class="form-style-2">
<%
//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
Date date = new Date();  
String strDate = formatter.format(date);
%>	
	<form action="RequisitionMultiController" method="post" name="frmSave">
		<div class="form-style-2-heading">Provide your information </div>
			<div class="square-44">
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field1"><span>Requisition ID <span class="required">*</span></span>
				<!-- generated auto increment id during add [S] -->
				<input type="text" class="input-field-60" readonly="readonly" name="requisition_id" id="requisition_id" value="${requisitionMultiId}"  maxlength=25 size=40 required />
				<!-- generated auto increment id during add [E] --> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field1"><span>Requisition ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="requisition_id" id="requisition_id" value="${requisitionMulti.requisition_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field2"><span>DateTime <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="date_time" id="date_time" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field2"><span>DateTime <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${requisitionMulti.date_time}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="date_time" id="date_time" value="${requisitionMulti.date_time}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field3"><span>Customer ID </span>
				<select name="customer_id" id="customer_id" class="select-field-60" onchange="customerChng();" >
					<option value="" >Select one</option>
					<c:forEach items="${allCustomer}" var="ac">
						<option value="${ac.customer_id}">${ac.customer_name}-${ac.customer_id}  -  ${ac.customer_name}  -  ${ac.mobile}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field3"><span>Customer ID </span>
				<select name="customer_id" id="customer_id" class="select-field-60" onchange="customerChng();" >
					<c:forEach items="${allCustomer}" var="ac">
						<option value="${ac.customer_id}" ${ac.customer_id == selectedCustomerId ? 'selected="selected"' : ''}>${ac.customer_id}  -  ${ac.customer_name}  -  ${ac.mobile}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field4"><span>Customer Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="customer_name" id="customer_name" value="${requisitionMulti.customer_name}" maxlength=40 size=40 required /> 
			</label>
			
			<label for="field5"><span>Mobile <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="mobile" id="mobile" value="${requisitionMulti.mobile}" maxlength=40 size=40 required /> 
			</label>
			
			<label for="field6"><span>Needed Date </span>
				<input type="text" class="input-field-60" name="needed_date_time" id="needed_date_time" value="${requisitionMulti.needed_date_time}"  maxlength=14 size=40 /> 
			</label>
			
			<%-- <label for="field7"><span>From Account </span>
				<input type="text" class="input-field-60" name="from_account_id" id="from_account_id" value="${requisitionMulti.from_account_id}"  maxlength=25 size=40 /> 
			</label> --%>
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field7"><span>From Account <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="from_account_id" id="from_account_id" value="${mainAccountId}"  maxlength=25 size=40 required /> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field7"><span>From Account <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="from_account_id" id="from_account_id" value="${requisitionMulti.from_account_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			</div>
			
			&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
			
			<div class="square-44">
			
			<label for="field8"><span>To Account </span>
				<input type="text" class="input-field-60" name="to_account_id" id="to_account_id" value="${requisitionMulti.to_account_id}"  maxlength=25 size=40 /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field9"><span>Salesman ID </span>
				<select name="salesman_id" id="salesman_id" class="select-field-60" >
					<option value="" >Select one</option>
					<c:forEach items="${allSalesman}" var="as">
						<option value="${as.salesman_id}">${as.salesman_id} - ${as.salesman_name}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field9"><span>Salesman ID </span>
				<select name="salesman_id" id="salesman_id" class="select-field-60" >
					<c:forEach items="${allSalesman}" var="as">
						<option value="${as.salesman_id}" ${as.salesman_id == selectedSalesmanId ? 'selected="selected"' : ''}>${as.salesman_id} - ${as.salesman_name}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field10"><span>Total Amount BDT. <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="total_amount" id="total_amount" value="0.00"  maxlength=10 size=40 required /> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field10"><span>Total Amount BDT. <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="total_amount" id="total_amount" value="${requisitionMulti.total_amount}"  maxlength=10 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%-- <label for="field11"><span>Order Status <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="order_status" id="order_status" value="${requisition.order_status}"  maxlength=1 size=40 required /> 
			</label> --%>
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field11"><span>Order Status </span>
				<select name="order_status" id="order_status" class="select-field-60" >
					<option value="P">Pending</option>
				</select> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field11"><span>Order Status </span>
				<select name="order_status" id="order_status" class="select-field-60" >
					<option value="" >Select one</option>
					<option value="P" ${requisitionMulti.order_status == 'P' ? 'selected="selected"' : ''}>Pending</option>
					<option value="A" ${requisitionMulti.order_status == 'A' ? 'selected="selected"' : ''}>Approved</option>
					<option value="C" ${requisitionMulti.order_status == 'C' ? 'selected="selected"' : ''}>Cancel</option>
					<option value="S" ${requisitionMulti.order_status == 'S' ? 'selected="selected"' : ''}>Success</option>
				</select> 
			</label>
			<%
			}
			%>
			
			<%-- <label for="field12"><span>Delivery Status <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="delivery_status" id="delivery_status" value="${requisition.delivery_status}"  maxlength=1 size=40 required /> 
			</label> --%>
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field12"><span>Delivery Status </span>
				<select name="delivery_status" id="delivery_status" class="select-field-60" >
					<option value="P">Pending</option>
				</select> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field12"><span>Delivery Status </span>
				<select name="delivery_status" id="delivery_status" class="select-field-60" >
					<option value="" >Select one</option>
					<option value="P" ${requisitionMulti.delivery_status == 'P' ? 'selected="selected"' : ''}>Pending</option>
					<option value="D" ${requisitionMulti.delivery_status == 'D' ? 'selected="selected"' : ''}>Delivered</option>
					<option value="S" ${requisitionMulti.delivery_status == 'S' ? 'selected="selected"' : ''}>Success</option>
					<option value="C" ${requisitionMulti.delivery_status == 'C' ? 'selected="selected"' : ''}>Cancel</option>
				</select> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field13"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="created" id="created" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field13"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${requisitionMulti.created}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="created" id="created" value="${requisitionMulti.created}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field14"><span>Updated </span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${requisitionMulti.updated}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="updated" id="updated" value="${requisitionMulti.updated}"  maxlength=14 size=40 /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field14"><span>Updated <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="updated" id="updated" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			</div>
			<br><br>
			<label><span></span>
					<input type="submit" value="Submit" />

					<a Class ="button" href="${pageContext.request.contextPath}/jsp/order/requisitionMulti.jsp">Return</a>
			</label>
			
	</form>
	</div>
		</div>	
	</div><!-- mcontent -->
	
</div><!-- main -->
</body>
</html>
<br>
<div>