<jsp:include page="../../base.jsp"></jsp:include>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<!DOCTYPE html>
<html>
<head>
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

		<div class="mcontent">
			<div class="titlenav">
				<ul>
					<li class="title"><a href="">Multi Requisition Enquiry</a></li>
					<li class="bread"><a href="">Dashboard > Order
							Management > Multi Requisition List > Multi Requisition Enquiry</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	
	<form action="" method="post">
		<table id="example" class="display" style="width: 100%" cellspacing="10">			
			<tr>
				<td Class ="FormCellColor" colspan="2">Requisition ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${requisitionMulti.requisition_id}" /></td>
				<td Class ="FormCellColor" colspan="2">DateTime</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${requisitionMulti.date_time}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${requisitionMulti.date_time}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Customer ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${requisitionMulti.customer_id}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Customer Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${requisitionMulti.customer_name}" /></td>
				<td Class ="FormCellColor" colspan="2">Mobile</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${requisitionMulti.mobile}" /></td>
				<td Class ="FormCellColor" colspan="2">Needed Date</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${requisitionMulti.needed_date_time}" /></td>
			</tr>
			
			<tr>			
				<td Class ="FormCellColor" colspan="2">From Account</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${requisitionMulti.from_account_id}" /></td>
				<td Class ="FormCellColor" colspan="2">To Account</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${requisitionMulti.to_account_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Salesman ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${requisitionMulti.salesman_id}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Total Amount</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${requisitionMulti.total_amount}" /></td>
				<td Class ="FormCellColor" colspan="2">Order Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${requisitionMulti.order_status == 'P' ? 'Pending' : requisitionMulti.order_status == 'A' ? 'Approved' : requisitionMulti.order_status == 'C' ? 'Cancel' : requisitionMulti.order_status == 'S' ? 'Success' : ''}" /></td>
				<td Class ="FormCellColor" colspan="2">Delivery Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${requisitionMulti.delivery_status == 'P' ? 'Pending' : requisitionMulti.delivery_status == 'D' ? 'Delivered' : requisitionMulti.delivery_status == 'C' ? 'Cancel' : requisitionMulti.delivery_status == 'S' ? 'Success' : ''}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${requisitionMulti.created}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${requisitionMulti.created}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Updated</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${requisitionMulti.updated}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${requisitionMulti.updated}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
		</table>
		<br>
		
		<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399><br>
						<%-- <a Class ="button" href="${pageContext.request.contextPath}/RequisitionMultiController?action=requisitionProductListEnquiry&requisition_id=${requisitionMulti.requisition_id}&date_time=${requisitionMulti.date_time}">Product Enquiry</a> --%>
						<a Class ="button" href="${pageContext.request.contextPath}/RequisitionMultiController?action=requisitionProductListEnquiry&requisition_id=${requisitionMulti.requisition_id}&date_time=${requisitionMulti.date_time}&customer_name=${requisitionMulti.customer_name}&mobile=${requisitionMulti.mobile}">Product Enquiry</a>
						<a Class ="button" href="${pageContext.request.contextPath}/jsp/order/requisitionMulti.jsp">Return</a></td>
					</td>
				</tr>
		</table>
	</form>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->

	<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

</body>
</html>