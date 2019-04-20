<jsp:include page="../../base.jsp"></jsp:include>
<br>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<!-- <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1"> -->
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet"
	href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/copytest.css" />
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/table.css" />

<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/jquery.min.js"></script>
<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/dataTables/jquery.dataTables.min.js"></script>
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/jquery.dataTables.min.css">
	
<title>onlinep</title>
<link rel="stylesheet" 	href="${pageContext.request.contextPath}/css/table.css">

<script type="text/javascript">

$(document).ready(function() {
	$('#example').DataTable();
});

function getRadioValue()
{
	var id = document.getElementsByName('requisition_product_id');
	var idValue;
	for(var i = 0; i < id.length; i++){
	    if(id[i].checked){
	    	idValue = id[i].value;
	    }
	}
	
	//for update [S]
	var updatePathWithIdValue = "${pageContext.request.contextPath}/RequisitionProductController?action=edit&requisition_product_id="+idValue;
	//for update [E]
	//for delete [S]
	var deletePathWithIdValue = "${pageContext.request.contextPath}/RequisitionProductController?action=delete&requisition_product_id="+idValue;
	//for delete [E]
	//for enquiry [S]
	var enquiryPathWithIdValue = "${pageContext.request.contextPath}/RequisitionProductController?action=enquiry&requisition_product_id="+idValue;
	//for enquiry [E]
	//for cancel [S]
	var cancelPathWithIdValue = "${pageContext.request.contextPath}/RequisitionProductController?action=cancel&requisition_product_id="+idValue;
	//for cancel [E]
	//for approve [S]
	var approvePathWithIdValue = "${pageContext.request.contextPath}/RequisitionProductController?action=approve&requisition_product_id="+idValue;
	//for approve [E]
	
	if (idValue !=null) {
		//for update [S]
		document.getElementById('update').href = updatePathWithIdValue;
		//for update [E]
		//for delete [S]
		document.getElementById('delete').href = deletePathWithIdValue;
		//for delete [E]
		//for enquiry [S]
		document.getElementById('enquiry').href = enquiryPathWithIdValue;
		//for enquiry [E]
		//for cancel [S]
		document.getElementById('cancel').href = cancelPathWithIdValue;
		//for cancel [E]
		//for approve [S]
		document.getElementById('approve').href = approvePathWithIdValue;
		//for approve [E]
	} else {
		alert("Please select a ID !!");
		return false;
	}
}

</script>
</head>
<body>

<%
String message = (String) request.getAttribute("success");
%>
	<table align="center">
				<%
				if(message!=null) {
				%>
				<tr>
					<th Class="HeaderTH"><%=message %></th>
				</tr>
				<%
				}
				%>
	</table>
	<br>
<div class="mcontent">
			<div class="titlenav">
			<ul>
					<li class="title"><a href="${pageContext.request.contextPath}/jsp/order/requisitionProduct.jsp">Product Requisition List</a></li>
					<li class="bread"><a href="">Dashboard > Order 
							Management > Multi Requisition List > Product Requisition List</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	<table class="display" style="width: 100%" cellspacing="10">			
		<tr>
			<td Class ="FormCellColor">Requisition ID</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${requisition_multi_id}" /></td>
			<td Class ="FormCellColor">DateTime</td>
			<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${strDateTimeMulti}" /></td> --%>
			<td Class ="FormInputColor" colspan="2">
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${strDateTimeMulti}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
			</td>
			<td Class ="FormCellColor">Customer Name</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${customerNameMulti}" /></td>
			<td Class ="FormCellColor">Mobile</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${customerMobileMulti}" /></td>
			<td Class ="FormCellColor">Total Amount</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${sumTotalAmount}" /></td>
		</tr>
	</table>
</div>
			<br>
<div class="card">
	
	<table id="example" class="display" style="width: 100%; font-size: 13px;">
		<thead>
			<tr>
				<th  Class ="HeaderTH"></th>
				<th Class ="HeaderTH">Product Requisition ID</th>
				<th Class ="HeaderTH">Requisition ID</th>
				<th Class ="HeaderTH">DateTime</th>
				<!-- <th Class ="HeaderTH">Product ID</th> -->
				<th Class ="HeaderTH">Product Name</th>
				<!-- <th Class ="HeaderTH">Pack Type</th>
				<th Class ="HeaderTH">Pack Size</th>
				<th Class ="HeaderTH">Pieces</th>
				<th Class ="HeaderTH">Bonus ID</th>
				<th Class ="HeaderTH">Bonus Name</th> -->
				<th Class ="HeaderTH">Order Pack</th>
				<th Class ="HeaderTH">Order Quantity</th>
				<th Class ="HeaderTH">MRP</th>
				<th Class ="HeaderTH">Total MRP</th>
				<th Class ="HeaderTH">Discount Amount</th>
				<th Class ="HeaderTH">Total Amount</th>
				<th Class ="HeaderTH">Order Status</th>
				<th Class ="HeaderTH">Delivery Status</th>
			</tr>
		</thead>
		
		<tbody>
			<c:forEach items="${requisitionProducts}" var="rp"> 
				<tr>
					<td Class ="FormInputColor"><input type="radio" name="requisition_product_id" id="requisition_product_id" value="${rp.requisition_product_id}" onclick="javascript: getRadioValue();" /></td>
					<td Class ="FormInputColor"><c:out value="${rp.requisition_product_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${rp.requisition_id}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${rp.date_time}" /></td> --%>
					<td Class ="FormInputColor">
						<fmt:parseDate pattern="yyyyMMddHHmmss" value="${rp.date_time}" var="parsedDate" />
						<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
					</td>
					<%-- <td Class ="FormInputColor"><c:out value="${rp.product_id}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${rp.product_name}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${rp.pack_type}" /></td>
					<td Class ="FormInputColor"><c:out value="${rp.pack_size}" /></td>
					<td Class ="FormInputColor"><c:out value="${rp.piceces}" /></td>
					<td Class ="FormInputColor"><c:out value="${rp.bonus_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${rp.bonus_name}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${rp.order_pack}" /></td>
					<td Class ="FormInputColor"><c:out value="${rp.order_quantity}" /></td>
					<td Class ="FormInputColor"><c:out value="${rp.mrp_price}" /> <br>Unit Price</td>
					<td Class ="FormInputColor"><c:out value="${rp.total_mrp_price}" /></td>
					<td Class ="FormInputColor"><c:out value="${rp.discount_amt}" /></td>
					<td Class ="FormInputColor"><c:out value="${rp.total_amount}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${rp.order_status}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${rp.order_status == 'P' ? 'Pending' : rp.order_status == 'A' ? 'Approved' : rp.order_status == 'C' ? 'Cancel' : rp.order_status == 'S' ? 'Success' : ''}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${r.delivery_status}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${rp.delivery_status == 'P' ? 'Pending' : rp.delivery_status == 'D' ? 'Delivered' : rp.delivery_status == 'C' ? 'Cancel' : rp.delivery_status == 'S' ? 'Success' : ''}" /></td>
				</tr>
			</c:forEach>
		</tbody>
	</table>
	<!-- for get Data from Multi Requisition [S] -->
	<input type="hidden" name="requisition_multi_id" id="requisition_multi_id" value="${requisition_multi_id}">
	<input type="hidden" name="strDateTimeMulti" id="strDateTimeMulti" value="${strDateTimeMulti}">
	<input type="hidden" name="customerNameMulti" id="customerNameMulti" value="${customerNameMulti}">
	<input type="hidden" name="customerMobileMulti" id="customerMobileMulti" value="${customerMobileMulti}">
	<%
	String requisition_multi_id = (String)request.getAttribute("requisition_multi_id");
	String strDateTimeMulti = (String)request.getAttribute("strDateTimeMulti");
	String customerNameMulti = (String)request.getAttribute("customerNameMulti");
	String customerMobileMulti = (String)request.getAttribute("customerMobileMulti");
	
	HttpSession session1 = request.getSession();
	session1.setAttribute("requisition_multi_id", requisition_multi_id);
	session1.setAttribute("strDateTimeMulti", strDateTimeMulti);
	session1.setAttribute("customerNameMulti", customerNameMulti);
	session1.setAttribute("customerMobileMulti", customerMobileMulti);
	%>
	<!-- for get Data from Multi Requisition [E] -->
	<br>
<input type="hidden" name="val" id="val" value="" />
	<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399>
					<br>
					<a Class ="button" href="${pageContext.request.contextPath}/RequisitionProductController?action=save">add</a>
					<a id="update" Class ="button" href="" onclick="javascript: getRadioValue();">update</a>
					<a id="approve" Class ="button" href="" onclick="javascript: getRadioValue();">approve</a>
					<a id="cancel" Class ="button" href="" onclick="javascript: getRadioValue();">cancel</a>
					<a id="delete" Class ="button" href="" onclick="javascript: getRadioValue();">delete</a>
					<a id="enquiry" Class ="button" href="" onclick="javascript: getRadioValue();">enquiry</a>
					<%-- <a Class ="button" href="${pageContext.request.contextPath}/requisitionMulti.jsp">Return</a></td> --%>
					<%-- <a Class ="button" href="${pageContext.request.contextPath}/RequisitionMultiController?action=requisitionMultiList&customer_name=${customerNameMulti}&mobile=${customerMobileMulti}">Return</a></td> --%>
					<a Class ="button" href="${pageContext.request.contextPath}/jsp/order/requisitionMulti.jsp">Return</a></td>
				</tr>
	</table>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->
	
</body>
</html>