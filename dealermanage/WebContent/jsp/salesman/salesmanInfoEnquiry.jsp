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
					<li class="title"><a href="">Salesman Enquiry</a></li>
					<li class="bread"><a href="">Dashboard > Salesman
							Management > Salesman List > Salesman Enquiry</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	
	<form action="" method="post">
		<table id="example" class="display" style="width: 100%" cellspacing="10">			
			<tr>
				<td Class ="FormCellColor" colspan="2">Salesman ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.salesman_id}" /></td>			
				<td Class ="FormCellColor" colspan="2">Salesman Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.salesman_name}" /></td>
				<td Class ="FormCellColor" colspan="2">Description</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.salesman_desc}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Salesman Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.salesman_type}" /></td>
				<td Class ="FormCellColor" colspan="2">Salesman Since</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.salesman_start_date}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${salesmanInfo.salesman_start_date}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Father Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.father_name}" /></td>
			</tr>
			<tr>
				<td Class ="FormCellColor" colspan="2">Mother Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.mother_name}" /></td>
				<td Class ="FormCellColor" colspan="2">NID No.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.nid}" /></td>
				<td Class ="FormCellColor" colspan="2">DOB</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.dob}" /></td>
			</tr>
			 
			<tr>
				<td Class ="FormCellColor" colspan="2">Occupation</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.occupation}" /></td>
				<td Class ="FormCellColor" colspan="2">Country ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.country_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Mobile</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.mobile}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Email</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.email}" /></td>
				<td Class ="FormCellColor" colspan="2">Account ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.account_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Home Address</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.home_address}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Office Address</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.office_address}" /></td>
				<td Class ="FormCellColor" colspan="2">Salesman Position</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.salesman_position}" /></td>
				<td Class ="FormCellColor" colspan="2">Status</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${customerInfo.status}" /></td> --%>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.status == 'A' ? 'Active' : salesmanInfo.status == 'R' ? 'Resigned' : salesmanInfo.status == 'T' ? 'Terminated' : salesmanInfo.status == 'I' ? 'Inactive' : salesmanInfo.status == 'B' ? 'Blocked' : salesmanInfo.status == 'C' ? 'Closed' : ''}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.created}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${salesmanInfo.created}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Updated</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${salesmanInfo.updated}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${salesmanInfo.updated}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
			
		</table>
		<br>
		
		<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399><br>
						<a Class ="button" href="${pageContext.request.contextPath}/jsp/salesman/salesmanInfo.jsp">Return</a>
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