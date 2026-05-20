import React from 'react';
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
} from '@dnd-kit/core';
import {
  SortableContext,
  arrayMove,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
} from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import Box from '@cloudscape-design/components/box';
import Badge from '@cloudscape-design/components/badge';

/**
 * Display metadata for the three CIA objectives — colour, label, and the
 * one-line "what does this protect" hint shown next to each row so users
 * who aren't fluent in CIA can rank without guessing.
 */
const OBJECTIVE_INFO = {
  confidentiality: {
    label: 'Confidentiality',
    description: 'Leaks and unauthorized data exposure are worst-case',
    color: 'severity-medium',
  },
  integrity: {
    label: 'Integrity',
    description: 'Tampering or corrupted data is worst-case',
    color: 'blue',
  },
  availability: {
    label: 'Availability',
    description: 'Downtime or denial-of-service is worst-case',
    color: 'green',
  },
};

const RANK_COLORS = ['red', 'severity-medium', 'grey'];
const RANK_LABELS = ['Most important', 'Second', 'Least important'];

function SortableRow({ id, rank }) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.5 : 1,
  };

  const info = OBJECTIVE_INFO[id];

  return (
    <div
      ref={setNodeRef}
      style={{
        ...style,
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        padding: '10px 12px',
        background: '#ffffff',
        border: '1px solid #d5dbdb',
        borderRadius: 6,
        cursor: 'grab',
      }}
      {...attributes}
      {...listeners}
      data-testid={`cia-priority-row-${id}`}
      aria-label={`${info.label}, currently ranked ${rank + 1} (${RANK_LABELS[rank]}). Use space then arrow keys to reorder.`}
    >
      {/* Drag handle glyph */}
      <span
        aria-hidden="true"
        style={{
          color: '#5f6b7a',
          fontSize: 18,
          lineHeight: 1,
          userSelect: 'none',
        }}
      >
        ⋮⋮
      </span>

      {/* Rank number */}
      <span
        style={{
          minWidth: 22,
          height: 22,
          borderRadius: 11,
          background: '#0972d3',
          color: '#ffffff',
          fontSize: 12,
          fontWeight: 700,
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        {rank + 1}
      </span>

      <div style={{ flex: 1 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <Badge color={info.color}>{info.label}</Badge>
          <span style={{ fontSize: 11, color: '#5f6b7a' }}>{RANK_LABELS[rank]}</span>
        </div>
        <Box variant="small" color="text-body-secondary" margin={{ top: 'xxs' }}>
          {info.description}
        </Box>
      </div>
    </div>
  );
}

/**
 * Drag-to-rank list of the three CIA objectives. Index 0 is most important.
 *
 * @param {Object} props
 * @param {string[]} props.value — current ordering (length 3)
 * @param {Function} props.onChange — receives the new ordering as a string[]
 */
export default function CiaPriorityList({ value, onChange }) {
  const sensors = useSensors(
    useSensor(PointerSensor),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

  function handleDragEnd(event) {
    const { active, over } = event;
    if (!over || active.id === over.id) return;
    const oldIndex = value.indexOf(active.id);
    const newIndex = value.indexOf(over.id);
    if (oldIndex < 0 || newIndex < 0) return;
    onChange(arrayMove(value, oldIndex, newIndex));
  }

  return (
    <div data-testid="cia-priority-list">
      <Box variant="small" color="text-body-secondary" margin={{ bottom: 'xs' }}>
        Drag the rows so the most important objective for this application
        sits at the top. The threat agent will weight generated threats roughly
        50% / 30% / 20% across rank 1, 2, and 3.
      </Box>
      <DndContext
        sensors={sensors}
        collisionDetection={closestCenter}
        onDragEnd={handleDragEnd}
      >
        <SortableContext items={value} strategy={verticalListSortingStrategy}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {value.map((id, idx) => (
              <SortableRow key={id} id={id} rank={idx} />
            ))}
          </div>
        </SortableContext>
      </DndContext>
    </div>
  );
}
