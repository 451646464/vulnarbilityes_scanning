from queue import PriorityQueue


# دالة لحساب المسافة مانهاتن
def manhattan_distance(state):
    distance = 0
    for i in range(3):
        for j in range(3):
            value = state[i][j]
            if value != 0:
                target_x = (value - 1) // 3
                target_y = (value - 1) % 3
                distance += abs(target_x - i) + abs(target_y - j)
    return distance


# دالة لتوليد الحالات الممكنة
def get_neighbors(state):
    neighbors = []
    row, col = [(i, j) for i in range(3) for j in range(3) if state[i][j] == 0][0]

    moves = [(-1, 0), (1, 0), (0, -1), (0, 1)]  # أعلى، أسفل، يسار، يمين
    for dr, dc in moves:
        new_row, new_col = row + dr, col + dc
        if 0 <= new_row < 3 and 0 <= new_col < 3:
            new_state = [list(r) for r in state]  # نسخ الحالة
            new_state[row][col], new_state[new_row][new_col] = new_state[new_row][new_col], new_state[row][col]
            neighbors.append(new_state)
    return neighbors


# دالة A* لحل اللعبة
def a_star(start):
    goal = [[1, 2, 3], [4, 5, 6], [7, 8, 0]]
    queue = PriorityQueue()
    queue.put((0, start, []))  # (التكلفة، الحالة، المسار)
    visited = set()

    while not queue.empty():
        cost, state, path = queue.get()

        # تحقق من الحالة النهائية
        if state == goal:
            return path + [state]  # إضافة الحالة النهائية إلى المسار

        state_tuple = tuple(map(tuple, state))  # تحويل الحالة إلى tuple لتخزينها في visited
        if state_tuple in visited:
            continue
        visited.add(state_tuple)

        # توليد الحالات المجاورة
        for neighbor in get_neighbors(state):
            new_cost = cost + 1 + manhattan_distance(neighbor)
            queue.put((new_cost, neighbor, path + [state]))  # إضافة الحالة الحالية إلى المسار

    return None  # إذا لم يتم العثور على حل


# مثال على الحالة الابتدائية
start_state = [[1, 2, 3], [4 , 6, 5], [7 , 0, 8]]  # هنا يمكنك تعديل الحالة
solution = a_star(start_state)

# عرض الحل
if solution is not None:
    print("خطوات الحل:")
    for step in solution:
        for row in step:
            print(row)
        print()
else:
    print("لا يوجد حل ممكن.")
